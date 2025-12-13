// ============================================
// Cookie Utilities
// Location: /src/utils/cookies.js
// ============================================

const Cookies = {
  // Set a cookie (expires in seconds)
  set: (name, value, expiresInSeconds = 3600) => {
    const expires = new Date(Date.now() + expiresInSeconds * 1000).toUTCString();
    document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Strict`;
  },

  // Get a cookie by name
  get: (name) => {
    const value = document.cookie.split('; ').find(row => row.startsWith(name + '='));
    return value ? decodeURIComponent(value.split('=')[1]) : null;
  },

  // Remove a cookie
  remove: (name) => {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }
};

export default Cookies;