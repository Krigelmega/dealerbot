// functions/api/[[route]].js

const store = {
    challenges: {},
    users: {},
    sessions: {}
};

export async function onRequest(context) {
    const { request } = context;
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

    // Регистрация - начало
    if (path === '/api/register/begin' && request.method === 'POST') {
        try {
            const { username } = await request.json();
            
            // Генерируем challenge
            const challenge = new Uint8Array(32);
            crypto.getRandomValues(challenge);
            
            // Сохраняем в памяти как строку
            store.challenges[username] = Array.from(challenge);
            
            // Отправляем challenge как массив чисел, а не base64
            const options = {
                challenge: Array.from(challenge),
                rp: {
                    name: "DealerBot",
                    id: url.hostname
                },
                user: {
                    id: Array.from(new TextEncoder().encode(username)),
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
            
            if (!store.challenges[username]) {
                return new Response(JSON.stringify({ error: 'Challenge expired' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            store.users[username] = {
                credentialId: id,
                publicKey: response.attestationObject,
                counter: 0
            };
            
            delete store.challenges[username];
            
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
            
            if (!store.users[username]) {
                return new Response(JSON.stringify({ error: 'User not found' }), {
                    status: 404,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const challenge = new Uint8Array(32);
            crypto.getRandomValues(challenge);
            
            store.challenges[username] = Array.from(challenge);
            
            const options = {
                challenge: Array.from(challenge),
                rpId: url.hostname,
                allowCredentials: [{
                    type: "public-key",
                    id: Array.from(new TextEncoder().encode(store.users[username].credentialId))
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
            
            if (!store.challenges[username]) {
                return new Response(JSON.stringify({ error: 'Challenge expired' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const sessionToken = new Uint8Array(32);
            crypto.getRandomValues(sessionToken);
            const token = Array.from(sessionToken).join('');
            store.sessions[token] = username;
            
            delete store.challenges[username];
            
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
            const username = store.sessions[sessionToken];
            
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
