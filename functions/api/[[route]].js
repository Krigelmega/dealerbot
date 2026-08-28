// functions/api/[[route]].js
export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname;

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
    }

    // Добавьте этот лог для отладки
    console.log('Request path:', path);
    console.log('Request method:', request.method);

    // Регистрация - начало
    if (path === '/api/register/begin' && request.method === 'POST') {
        try {
            const { username } = await request.json();
            
            const challenge = new Uint8Array(32);
            crypto.getRandomValues(challenge);
            
            await env.SESSION_STORE.put(`challenge:${username}`, btoa(String.fromCharCode(...challenge)), { expirationTtl: 300 });
            
            const options = {
                challenge: btoa(String.fromCharCode(...challenge)),
                rp: {
                    name: "DealerBot",
                    id: url.hostname
                },
                user: {
                    id: btoa(String.fromCharCode(...new TextEncoder().encode(username))),
                    name: username,
                    displayName: username
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },
                    { type: "public-key", alg: -257 }
                ],
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required"
                },
                timeout: 60000,
                attestation: "none"
            };
            
            return new Response(JSON.stringify(options), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }

    // Регистрация - завершение
    if (path === '/api/register/complete' && request.method === 'POST') {
        try {
            const data = await request.json();
            const { username, id, response } = data;
            
            const storedChallenge = await env.SESSION_STORE.get(`challenge:${username}`);
            if (!storedChallenge) {
                return new Response(JSON.stringify({ error: 'Challenge expired' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            await env.SESSION_STORE.put(`user:${username}`, JSON.stringify({
                credentialId: id,
                publicKey: response.attestationObject,
                counter: 0
            }));
            
            await env.SESSION_STORE.delete(`challenge:${username}`);
            
            return new Response(JSON.stringify({ success: true }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }

    // Вход - начало
    if (path === '/api/login/begin' && request.method === 'POST') {
        try {
            const { username } = await request.json();
            const userData = await env.SESSION_STORE.get(`user:${username}`);
            
            if (!userData) {
                return new Response(JSON.stringify({ error: 'User not found' }), {
                    status: 404,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const user = JSON.parse(userData);
            const challenge = new Uint8Array(32);
            crypto.getRandomValues(challenge);
            
            await env.SESSION_STORE.put(`challenge:${username}`, btoa(String.fromCharCode(...challenge)), { expirationTtl: 300 });
            
            const options = {
                challenge: btoa(String.fromCharCode(...challenge)),
                rpId: url.hostname,
                allowCredentials: [{
                    type: "public-key",
                    id: user.credentialId
                }],
                userVerification: "required",
                timeout: 60000
            };
            
            return new Response(JSON.stringify(options), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }

    // Вход - завершение
    if (path === '/api/login/complete' && request.method === 'POST') {
        try {
            const data = await request.json();
            const { username, id, response } = data;
            
            const storedChallenge = await env.SESSION_STORE.get(`challenge:${username}`);
            if (!storedChallenge) {
                return new Response(JSON.stringify({ error: 'Challenge expired' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const sessionToken = new Uint8Array(32);
            crypto.getRandomValues(sessionToken);
            const token = btoa(String.fromCharCode(...sessionToken));
            await env.SESSION_STORE.put(`session:${token}`, username, { expirationTtl: 86400 });
            
            await env.SESSION_STORE.delete(`challenge:${username}`);
            
            return new Response(JSON.stringify({ 
                success: true, 
                sessionToken: token 
            }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }

    // Проверка сессии
    if (path === '/api/check-session' && request.method === 'POST') {
        try {
            const { sessionToken } = await request.json();
            const username = await env.SESSION_STORE.get(`session:${sessionToken}`);
            
            return new Response(JSON.stringify({ 
                authenticated: !!username,
                username: username
            }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }

    return new Response(JSON.stringify({ error: 'Not found' }), { 
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
}
