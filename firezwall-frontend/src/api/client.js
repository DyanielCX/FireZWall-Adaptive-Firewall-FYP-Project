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


  // Refresh Token - POST /api/refresh-token
  refreshToken: async (refreshToken) => {
    const response = await fetch(`${BASE_URL}/refresh-token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        refresh_token: refreshToken
      })
    });
    if (!response.ok) throw new Error('Token refresh failed');
    return response.json();
  },


  // View Users - GET /api/user/view
  getUsers: async (token, role = null) => {
    const body = {};
    
    // Only include role filter if provided
    if (role && role !== 'all') {
      body.role = role;
    }

    const response = await fetch(`${BASE_URL}/user/view`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw {
        status: response.status,
        message: errorData.message || errorData.error || 'Failed to fetch users'
      };
    }
    return response.json();
  },


  // Register Users - POST /api/user/register
  registerUser: async (token, userData) => {
    const response = await fetch(`${BASE_URL}/user/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        username: userData.username,
        password: userData.password,
        role: userData.role
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw {
        status: response.status,
        message: errorData.message || errorData.error || 'Failed to register user'
      };
    }
    return response.json();
  },


  // Delete Users - DELETE /api/user/delete
  deleteUser: async (token, username) => {
    const response = await fetch(`${BASE_URL}/user/delete`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        username: username
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw {
        status: response.status,
        message: errorData.message || errorData.error || 'Failed to delete user'
      };
    }
    return response.json();
  },


  // Get User Role - GET /api/user/getRole
  getUserRole: async (token) => {
    const response = await fetch(`${BASE_URL}/user/getRole`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    if (!response.ok) throw new Error('Failed to fetch user role');
    return response.json();
  },


  // Get Username - GET /api/user/getUsername
  getUserName: async (token) => {
    const response = await fetch(`${BASE_URL}/user/getUsername`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    if (!response.ok) throw new Error('Failed to fetch username');
    return response.json();
  },


  // View Firewall Rules - GET /api/firewall/status
  getFirewallRules: async (token) => {
    const response = await fetch(`${BASE_URL}/firewall/status`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to fetch firewall rules');
    return response.json();
  },


  // Add Firewall Rules - POST /api/firewall
  addFirewallRule: async (token, ruleData) => {
    
    const body = {}; // Only include fields that have values
    
    // action, protocol & direction (required fields)
    if (ruleData.action) body.action = ruleData.action;
    if (ruleData.protocol) body.protocol = ruleData.protocol;
    if (ruleData.direction) body.direction = ruleData.direction;
    
    // Optional: port OR service (only one needed)
    if (ruleData.port && ruleData.port.trim() !== '') {
      body.port = ruleData.port;
    } else if (ruleData.service && ruleData.service.trim() !== '') {
      body.service = ruleData.service;
    }
    
    // IPv4 & IPv6 (always include)
    body.ipv4 = ruleData.ipv4 === true;
    body.ipv6 = ruleData.ipv6 === true;
    
    // Optional: source (only if provided)
    if (ruleData.source && ruleData.source.trim() !== '') {
      body.source = ruleData.source;
    }

    console.log('Sending firewall rule:', body);

    const response = await fetch(`${BASE_URL}/firewall`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw {
        status: response.status,
        message: errorData.message || errorData.error || 'Failed to add firewall rule'
      };
    }
    
    return response.json();
  },


  // Delete Firewall Rules - DELETE /api/firewall
  deleteFirewallRule: async (token, ruleData) => {
    
    const body = {}; // Only include fields that have values
    
    // action, protocol, direction & port (required fields)
    if (ruleData.action) body.action = ruleData.action;
    if (ruleData.protocol) body.protocol = ruleData.protocol;
    if (ruleData.direction) body.direction = ruleData.direction;
    if (ruleData.port) body.port = ruleData.port;
    
    // IPv4 & IPv6 (always include)
    body.ipv4 = ruleData.ipv4 === true;
    body.ipv6 = ruleData.ipv6 === true;
    
    // source (only if provided)
    if (ruleData.source && ruleData.source.trim() !== '' && ruleData.source.toLowerCase() !== 'anywhere') {
      body.source = ruleData.source;
    }

    console.log('Deleting firewall rule:', body);

    const response = await fetch(`${BASE_URL}/firewall`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw {
        status: response.status,
        message: errorData.message || errorData.error || 'Failed to delete firewall rule'
      };
    }
    
    return response.json();
  },


  // View Honeypot Reports - GET /api/honeypot/reports
  getHoneypots: async (token, event_type, ip, protocol, timestamp) => {
    const response = await fetch(`${BASE_URL}/honeypot/reports`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        event_type: event_type,
        ip: ip,
        protocol: protocol,
        timestamp: timestamp
      })
    });
    if (!response.ok) throw new Error('Failed to fetch honeypot reports');
    return response.json();
  },

  // View Syslogs - GET /api/logs
  getSyslogs: async (token, timestamp, level, module, username, endpoint) => {  
    const response = await fetch(`${BASE_URL}/logs`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        timestamp: timestamp,
        level: level,
        module: module,
        username: username,
        endpoint: endpoint
      })
    });
    if (!response.ok) throw new Error('Failed to fetch syslogs');
    return response.json();
  }
};

export default apiClient;