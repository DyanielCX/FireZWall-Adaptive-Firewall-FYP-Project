// ============================================
// Updated AuthContext with Token Auto-Refresh
// Location: /src/context/AuthContext.jsx  
// ============================================
import { createContext, useState, useContext, useEffect } from 'react';
import apiClient from '../api/client';
import tokenManager from '../utils/tokenManager';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize on mount
  useEffect(() => {
    console.log('AuthContext initializing...');
    // Initialize token manager (will set up auto-refresh if token exists)
    tokenManager.initialize();
    
    // Check if user is logged in
    const token = tokenManager.getAccessToken();
    if (token) {
      // Token exists, user is logged in
      setUser({ token });
      console.log('User restored from token');
    } else {
      console.log('No token found, user not logged in');
    }
    
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    console.log('Login function called with username:', username);
    
    try {
      // Use apiClient.login instead of duplicating the code
      const data = await apiClient.login(username, password);
      
      console.log('Login response data:', { 
        has_access_token: !!data.access_token, 
        has_refresh_token: !!data.refresh_token,
        expires_in: data.expires_in 
      });
      
      // Store tokens using token manager (will set up auto-refresh)
      tokenManager.setTokens(
        data.access_token,
        data.refresh_token,
        data.expires_in
      );

      setUser({ username, token: data.access_token });
      console.log('Login successful, user set');
      
      // Don't throw or return here - just complete successfully
    } catch (error) {
      console.error('Login error:', error);
      throw error; // Throw the error so Login component can catch it
    }
  };

  const logout = async () => {
    console.log('Logout function called');
    
    try {
      // Retrieve Token
      const token = tokenManager.getAccessToken();
      
      // Call logout API 
      if (token) {
        console.log('Calling logout API...');
        await apiClient.logout(token);
        console.log('Logout API call successful');
      }

    // Console Error Shown
    } catch (error) {
      console.error('Logout API error (continuing with local logout):', error);
    } finally {
      // Clear cookies and cancel token auto refresh
      tokenManager.clearTokens();
      setUser(null);
      console.log('Tokens cleared, redirecting to login...');
      window.location.href = '/login';
    }
  };

  const value = {
    user,
    login,
    logout,
    loading,
    isAuthenticated: !!user,
  };

  if (loading) {
    return null; // Or a loading spinner
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};