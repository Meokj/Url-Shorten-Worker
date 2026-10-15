const config = {
	no_ref: "off", //Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
	theme: "theme/captcha", //Homepage theme, use the empty value for default theme. To use urlcool theme, please fill with "theme/urlcool" . If you need captcha feature, you need to use captcha theme.
	cors: "on", //Allow Cross-origin resource sharing for API requests.
	unique_link: true, //If it is true, the same long url will be shorten into the same short url
	custom_link: false, //Allow users to customize the short url.
	safe_browsing_api_key: "", //Enter Google Safe Browsing API Key to enable url safety check before redirect.
	expiration_ttl: 0, // Short link expiration time in seconds. 86400 = 24 hours. Set to 0 for no expiration.

	// CAPTCHA Configuration
	captcha: {
		enabled: false, // Master switch for CAPTCHA service
		api_endpoint: "https://captcha.gurl.eu.org/api", // CAP Worker API endpoint
		require_on_create: false, // Require CAPTCHA when creating short links
		require_on_access: false, // Require CAPTCHA when accessing short links
		timeout: 5000, // API request timeout in milliseconds
		fallback_on_error: true, // Allow operations when CAPTCHA service is down
		max_retries: 2, // Maximum retry attempts for CAPTCHA API calls
	}
}

const html404 = `<!DOCTYPE html>
  <body>
    <h1>404 Not Found.</h1>
    <p>The url you visit is not found.</p>
    <a href="https://github.com/xyTom/Url-Shorten-Worker/" target="_self">Fork me on GitHub</a>
  </body>`

let response_header = {
	"content-type": "text/html;charset=UTF-8",
}

if (config.cors == "on") {
	response_header = {
		"content-type": "text/html;charset=UTF-8",
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Methods": "POST",
	}
}

async function randomString(len) {
	len = len || 6;
	let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
	let maxPos = $chars.length;
	let result = '';
	for (let i = 0; i < len; i++) {
		result += $chars.charAt(Math.floor(Math.random() * maxPos));
	}
	return result;
}

async function sha512(url) {
	url = new TextEncoder().encode(url)
	const url_digest = await crypto.subtle.digest({
			name: "SHA-512",
		},
		url,
	)
	const hashArray = Array.from(new Uint8Array(url_digest));
	const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
	return hashHex
}

async function checkURL(URL) {
	let str = URL;
	let Expression = /http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
	let objExp = new RegExp(Expression);
	if (objExp.test(str) == true) {
		if (str[0] == 'h')
			return true;
		else
			return false;
	} else {
		return false;
	}
}

function getKvPutOptions(requestCustomTtl) {
	const MIN_TTL = 60;
	const MAX_TTL = 31536000;
	const DEFAULT_TTL = 86400;

	if (requestCustomTtl !== undefined && requestCustomTtl !== null && requestCustomTtl !== '') {
		let parsedTtl = requestCustomTtl;
		if (typeof requestCustomTtl === 'string') {
			parsedTtl = Number(requestCustomTtl);
		}

		if (typeof parsedTtl !== 'number' || isNaN(parsedTtl) || !Number.isInteger(parsedTtl)) {
			throw new Error("Invalid TTL: ttl must be a pure integer number or numeric string.");
		}

		const isValidRange = requestCustomTtl >= MIN_TTL && requestCustomTtl <= MAX_TTL;
		if (!isValidRange) {
			throw new Error(`Invalid TTL: ttl must be between ${MIN_TTL} and ${MAX_TTL} seconds (inclusive).`);
		}
		
		return {
			expirationTtl: requestCustomTtl
		};
	}

	const configTtl = Number(config.expiration_ttl);
	if (Number.isFinite(configTtl) && configTtl >= MIN_TTL && configTtl <= MAX_TTL) {
		return {
			expirationTtl: Math.floor(configTtl)
		};
	}

	return {
		expirationTtl: DEFAULT_TTL
	};
}

async function save_url(URL, customTtl) {
	let random_key = await randomString()
	let is_exist = await LINKS.get(random_key)
	
	if (is_exist == null) {
		const options = getKvPutOptions(customTtl); 
		await LINKS.put(random_key, URL, options);
		return random_key;
	} else {
		return await save_url(URL, customTtl)
	}
}

async function is_url_exist(url_sha512) {
	let is_exist = await LINKS.get(url_sha512)
	if (is_exist == null) {
		return false
	} else {
		return is_exist
	}
}

async function is_url_safe(url) {
	let raw = JSON.stringify({
		"client": {
			"clientId": "Url-Shorten-Worker",
			"clientVersion": "1.0.7"
		},
		"threatInfo": {
			"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
			"platformTypes": ["ANY_PLATFORM"],
			"threatEntryTypes": ["URL"],
			"threatEntries": [{
				"url": url
			}]
		}
	});

	let requestOptions = {
		method: 'POST',
		body: raw,
		redirect: 'follow'
	};

	let result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + config.safe_browsing_api_key, requestOptions)
	result = await result.json()
	if (Object.keys(result).length === 0) {
		return true
	} else {
		return false
	}
}

async function validateCaptchaToken(token, keepToken = false) {
	if (!config.captcha.enabled) {
		return {
			success: true,
			degraded: false
		};
	}

	if (!token || typeof token !== 'string' || token.length < 10) {
		return {
			success: false,
			error: 'Invalid token format'
		};
	}

	let lastError = null;
	const maxRetries = config.captcha.max_retries || 2;

	for (let attempt = 0; attempt <= maxRetries; attempt++) {
		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), config.captcha.timeout);

			const response = await fetch(`${config.captcha.api_endpoint}/validate`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'User-Agent': 'Url-Shorten-Worker/1.0.7',
				},
				body: JSON.stringify({
					token,
					keepToken
				}),
				signal: controller.signal,
			});

			clearTimeout(timeoutId);

			if (response.ok) {
				const result = await response.json();
				return {
					success: result.success === true,
					degraded: false
				};
			}

			if (response.status === 400 || response.status === 410 || response.status === 404 || response.status === 409) {
				return {
					success: false,
					error: 'Invalid or expired token'
				};
			}

			lastError = `HTTP ${response.status}`;
		} catch (error) {
			lastError = error.name === 'AbortError' ? 'Timeout' : error.message;
			if (attempt < maxRetries) {
				await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
			}
		}
	}

	if (config.captcha.fallback_on_error) {
		return {
			success: true,
			degraded: true
		};
	}

	return {
		success: false,
		error: lastError || 'CAPTCHA service unavailable'
	};
}

function isCaptchaRequired(operation) {
	if (!config.captcha.enabled) {
		return false;
	}

	switch (operation) {
		case 'create':
			return config.captcha.require_on_create;
		case 'access':
			return config.captcha.require_on_access;
		default:
			return false;
	}
}

async function extractCaptchaToken(request) {
	const contentType = request.headers.get('content-type') || '';

	if (contentType.includes('application/json')) {
		try {
			const body = await request.clone().json();
			return body.captcha_token || body.captchaToken || body.token || null;
		} catch {
			return null;
		}
	}

	const url = new URL(request.url);
	return url.searchParams.get('captcha_token') || url.searchParams.get('token') || null;
}

async function handleRequest(request) {
	// Handle POST request - Create short link
	if (request.method === "POST") {
		try {
			let req = await request.json();
			let customTtl = req["ttl"];

			// Validate URL format
			if (!await checkURL(req["url"])) {
				return new Response(JSON.stringify({
					status: 500,
					error: "Invalid URL format"
				}), {
					headers: response_header,
					status: 400
				});
			}

			// CAPTCHA validation for link creation
			if (isCaptchaRequired('create')) {
				const captchaToken = req.captcha_token || req.captchaToken || req.token;

				if (!captchaToken) {
					return new Response(JSON.stringify({
						status: 403,
						error: "CAPTCHA token required",
						captcha_required: true
					}), {
						headers: response_header,
						status: 403
					});
				}

				const validation = await validateCaptchaToken(captchaToken, false);

				if (!validation.success) {
					return new Response(JSON.stringify({
						status: 403,
						error: validation.error || "CAPTCHA verification failed",
						captcha_required: true
					}), {
						headers: response_header,
						status: 403
					});
				}
			}

			let random_key;
			if (config.unique_link) {
				let url_sha512 = await sha512(req["url"]);
				let url_key = await is_url_exist(url_sha512);
				if (url_key) {
					random_key = url_key;
				} else {
					random_key = await save_url(req["url"], customTtl);
					await LINKS.put(url_sha512, random_key, getKvPutOptions(customTtl));
				}
			} else {
				random_key = await save_url(req["url"], customTtl);
			}

			if (!random_key) {
				return new Response(JSON.stringify({
					status: 500,
					error: "Reached KV write limitation"
				}), {
					headers: response_header,
					status: 500
				});
			}

			const host = request.headers.get('host');
			let cleaned_key = random_key.startsWith('/') ? random_key.substring(1) : random_key;
			let short_url = `https://${host}/${cleaned_key}`;

			return new Response(JSON.stringify({
				status: 200,
				key: "/" + cleaned_key,
				short_url: short_url
			}), {
				headers: {
					...response_header,
					"content-type": "application/json;charset=UTF-8"
				},
				status: 200
			});

		} catch (err) {
			return new Response(JSON.stringify({
				status: 400,
				error: err.message  
			}), {
				status: 400,
				headers: response_header  
			});
		}
	} else if (request.method === "OPTIONS") {
		return new Response("", {
			headers: response_header,
		});
	}

	// Handle GET request - Access short link
	const requestURL = new URL(request.url);
	const path = requestURL.pathname.split("/")[1];
	const params = requestURL.search;

	// Serve homepage
	if (!path) {
		const html = await fetch("https://xytom.github.io/Url-Shorten-Worker/" + config.theme + "/index.html");
		return new Response(await html.text(), {
			headers: {
				"content-type": "text/html;charset=UTF-8",
			},
		});
	}

	// Retrieve the target URL
	const value = await LINKS.get(path);
	let location;

	if (params) {
		location = value + params;
	} else {
		location = value;
	}

	if (location) {
		if (isCaptchaRequired('access')) {
			const captchaToken = await extractCaptchaToken(request);

			if (!captchaToken) {
				const captchaPage = `<!DOCTYPE html>...`; // (此处省略部分保持原样或保留你原本的验证码页面模板)
				return new Response(captchaPage, {
					headers: { "content-type": "text/html;charset=UTF-8" },
					status: 403
				});
			}

			const validation = await validateCaptchaToken(captchaToken, false);
			if (!validation.success) {
				return new Response(`Verification Failed`, {
					headers: { "content-type": "text/html;charset=UTF-8" },
					status: 403
				});
			}
		}

		if (config.safe_browsing_api_key) {
			if (!(await is_url_safe(location))) {
				let warning_page = await fetch("https://xytom.github.io/Url-Shorten-Worker/safe-browsing.html");
				warning_page = await warning_page.text();
				warning_page = warning_page.replace(/{Replace}/gm, location);
				return new Response(warning_page, {
					headers: {
						"content-type": "text/html;charset=UTF-8",
					},
				});
			}
		}

		if (config.no_ref == "on") {
			let no_ref = await fetch("https://xytom.github.io/Url-Shorten-Worker/no-ref.html");
			no_ref = await no_ref.text();
			no_ref = no_ref.replace(/{Replace}/gm, location);
			return new Response(no_ref, {
				headers: {
					"content-type": "text/html;charset=UTF-8",
				},
			});
		} else {
			return Response.redirect(location, 302);
		}
	}

	return new Response(html404, {
		headers: {
			"content-type": "text/html;charset=UTF-8",
		},
		status: 404
	});
}

addEventListener("fetch", async event => {
	event.respondWith(handleRequest(event.request));
});
