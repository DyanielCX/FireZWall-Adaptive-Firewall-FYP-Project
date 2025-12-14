// ============================================
// API Utility with Automatic Token Refresh
// Location: /src/utils/api.js
// ============================================
import tokenManager from './tokenManager';

/**
 * Enhanced fetch wrapper with automatic token refresh
 * Use this instead of regular fetch() for authenticated API calls
 * 
 * Usage:
 *   const response = await apiFetch('/api/firewall', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify(data)
 *   });
 */

export const apiFetch = async (url, options = {}) => {
  // Get valid token (will refresh if needed)
  const token = await tokenManager.getValidToken();
  
  if (!token) {
    // No valid token available, redirect to login
    window.location.href = '/login';
    throw new Error('No valid authentication token');
  }

  // Add authorization header
  const headers = {
    ...options.headers,
    'Authorization': `Bearer ${token}`,
  };

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    // If token expired (401), try to refresh and retry once
    if (response.status === 401) {
      console.log('Got 401, attempting token refresh...');
      
      const newToken = await tokenManager.refreshToken();
      
      if (!newToken) {
        // Refresh failed, user will be logged out by tokenManager
        throw new Error('Token refresh failed');
      }

      // Retry request with new token
      headers['Authorization'] = `Bearer ${newToken}`;
      const retryResponse = await fetch(url, {
        ...options,
        headers,
      });

      return retryResponse;
    }

    return response;
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
};

export default apiFetch;