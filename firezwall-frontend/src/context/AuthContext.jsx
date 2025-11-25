import { createContext, useContext, useState, useEffect } from 'react';
import Cookies from '../utils/cookies';
import apiClient from '../api/client';

// Create Auth Context
const AuthContext = createContext(null);

// Auth Provider Component
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check for existing token on mount
  useEffect(() => {
    const token = Cookies.get('access_token');
    if (token) {
      setUser({ token });
    }
    setLoading(false);
  }, []);

  // Login function
  const login = async (username, password) => {
    const data = await apiClient.login(username, password);
    
    // Save tokens to cookies
    Cookies.set('access_token', data.access_token);
    Cookies.set('refresh_token', data.refresh_token);
    
    // Update user state
    setUser({ token: data.access_token });
    
    return data;
  };

  // Logout function
  const logout = async () => {
    
    try{
      // Get the token from cookies
      const token = Cookies.get('access_token');

      // Call API logout
      if(token){
        await apiClient.logout(token);
      }
    } catch (error){
      console.error('Logout API error:', error);
    }
    finally {
      // Continue for frontend logout although API logout fail
      Cookies.remove('access_token');
      Cookies.remove('refresh_token');
      setUser(null);
    }
  };

  // Check if user is authenticated
  const isAuthenticated = () => {
    return !!Cookies.get('access_token');
  };

  // Get access token
  const getToken = () => {
    return Cookies.get('access_token');
  };

  return (
    <AuthContext.Provider value={{ 
      user, 
      login, 
      logout, 
      isAuthenticated, 
      getToken,
      loading 
    }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;