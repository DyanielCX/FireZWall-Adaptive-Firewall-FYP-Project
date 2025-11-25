// ============================================
//             API CONFIGURATION
// ============================================

export const BASE_URL = "/api";

const apiClient = {
  // Login - POST /api/login
  login: async (username, password) => {
    try {
      console.log('Making request to:', `${BASE_URL}/login`);
      
      const response = await fetch(`${BASE_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          username: username,
          password: password
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw {
          status: response.status,
          message: errorData.message || errorData.error || `HTTP Error ${response.status}`
        };
      }

      const data = await response.json();
      return data;
    } catch (error) {
      if (error.status) throw error;
      throw { status: 0, message: error.message || 'Network error' };
    }
  },

  // Logout - POST /api/logout
  logout: async (token) => {
    const response = await fetch(`${BASE_URL}/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });
    if (!response.ok) throw new Error('Failed to logout');
    return response.json();
  },

  // Other methods remain the same, just use BASE_URL
  refreshToken: async (refreshToken) => {
    const response = await fetch(`${BASE_URL}/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${refreshToken}`
      }
    });
    if (!response.ok) throw new Error('Token refresh failed');
    return response.json();
  },

  getUsers: async (token) => {
    const response = await fetch(`${BASE_URL}/users`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to fetch users');
    return response.json();
  },

  getFirewallRules: async (token) => {
    const response = await fetch(`${BASE_URL}/firewall/rules`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to fetch firewall rules');
    return response.json();
  },

  getHoneypots: async (token) => {
    const response = await fetch(`${BASE_URL}/honeypots`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to fetch honeypots');
    return response.json();
  },

  getLogs: async (token) => {
    const response = await fetch(`${BASE_URL}/logs`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to fetch logs');
    return response.json();
  }
};

export default apiClient;