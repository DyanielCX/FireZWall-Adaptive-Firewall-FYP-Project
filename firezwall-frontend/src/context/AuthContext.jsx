// ============================================
// Updated AuthContext with Token Auto-Refresh
// Location: /src/contexts/AuthContext.jsx
// ============================================
import { createContext, useState, useContext, useEffect } from 'react';
import tokenManager from '../utils/tokenManager';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize on mount
  useEffect(() => {
    // Initialize token manager (will set up auto-refresh if token exists)
    tokenManager.initialize();
    
    // Check if user is logged in
    const token = tokenManager.getAccessToken();
    if (token) {
      // You might want to fetch user info here
      setUser({ token }); // Simplified, replace with actual user data
    }
    
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        throw new Error('Login failed');
      }

      const data = await response.json();
      
      // Store tokens using token manager (will set up auto-refresh)
      tokenManager.setTokens(
        data.access_token,
        data.refresh_token,
        data.expires_in
      );

      setUser({ username, token: data.access_token });
      return { success: true };
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    tokenManager.clearTokens();
    setUser(null);
    window.location.href = '/login';
  };

  const value = {
    user,
    login,
    logout,
    loading,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};