import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10_000,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('grc_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
    // Stamp the token on the config so the error interceptor can tell
    // whether the token has been refreshed since this request was sent.
    (config as any)._sentToken = token;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      const sentToken = (error.config as any)?._sentToken;
      const currentToken = localStorage.getItem('grc_token');

      // Only clear + redirect when the token that failed is still the
      // current one.  A newer token means another request (e.g. login)
      // already replaced it — don't nuke the fresh token.
      if (!currentToken || currentToken === sentToken) {
        localStorage.removeItem('grc_token');
        const path = window.location.pathname;
        if (path !== '/login' && path !== '/register' && path !== '/auditor-login') {
          window.location.href = path.startsWith('/auditor') ? '/auditor-login' : '/login';
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;
