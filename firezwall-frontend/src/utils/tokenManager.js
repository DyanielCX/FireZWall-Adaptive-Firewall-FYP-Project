// ============================================
// Token Management Utility with Auto-Refresh
// Location: /src/utils/tokenManager.js
// ============================================
import Cookies from './cookies';

const TOKEN_COOKIE_NAME = 'access_token';
const REFRESH_TOKEN_COOKIE_NAME = 'refresh_token';
const REFRESH_BUFFER_TIME = 300; // Refresh 5 minutes before expiry

class TokenManager {
  constructor() {
    this.refreshTimeout = null;
    this.isRefreshing = false;
    this.refreshPromise = null;
    this.tokenExpiryTime = null; // Store expiry time in memory, not in cookie
  }

  /**
   * Store tokens and set up auto-refresh
   */
  setTokens(accessToken, refreshToken, expiresIn) {
    // Store tokens in cookies (expiresIn is in seconds from API)
    Cookies.set(TOKEN_COOKIE_NAME, accessToken, expiresIn);
    Cookies.set(REFRESH_TOKEN_COOKIE_NAME, refreshToken, expiresIn * 2); // Refresh token lasts longer
    
    // Calculate and store expiry time in memory (current time + expires_in seconds)
    this.tokenExpiryTime = Date.now() + (expiresIn * 1000);
    
    // Schedule token refresh
    this.scheduleTokenRefresh(expiresIn);
    
    console.log(`Token stored in cookies. Expires in ${expiresIn} seconds (${new Date(this.tokenExpiryTime).toLocaleString()})`);
  }

  /**
   * Get current access token
   */
  getAccessToken() {
    return Cookies.get(TOKEN_COOKIE_NAME);
  }

  /**
   * Get refresh token
   */
  getRefreshToken() {
    return Cookies.get(REFRESH_TOKEN_COOKIE_NAME);
  }

  /**
   * Get token expiry time
   */
  getTokenExpiry() {
    return this.tokenExpiryTime;
  }

  /**
   * Check if token is expired or about to expire
   */
  isTokenExpired() {
    const expiry = this.getTokenExpiry();
    if (!expiry) return true;
    
    // Consider token expired if it expires in less than 1 minute
    return Date.now() >= (expiry - 60000);
  }

  /**
   * Check if token needs refresh (5 minutes before expiry)
   */
  shouldRefreshToken() {
    const expiry = this.getTokenExpiry();
    if (!expiry) return true;
    
    // Refresh if token expires in less than REFRESH_BUFFER_TIME seconds
    return Date.now() >= (expiry - (REFRESH_BUFFER_TIME * 1000));
  }

  /**
   * Schedule automatic token refresh
   */
  scheduleTokenRefresh(expiresIn) {
    // Clear any existing timeout
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }

    // Schedule refresh REFRESH_BUFFER_TIME seconds before expiry
    const refreshTime = (expiresIn - REFRESH_BUFFER_TIME) * 1000;
    
    // Make sure refresh time is positive
    if (refreshTime > 0) {
      this.refreshTimeout = setTimeout(() => {
        console.log('Auto-refreshing token...');
        this.refreshToken();
      }, refreshTime);
      
      console.log(`Token refresh scheduled in ${refreshTime / 1000} seconds`);
    } else {
      // Token expires too soon, refresh immediately
      console.log('Token expires soon, refreshing immediately...');
      this.refreshToken();
    }
  }

  /**
   * Refresh the access token
   */
  async refreshToken() {
    // Prevent multiple simultaneous refresh requests
    if (this.isRefreshing) {
      return this.refreshPromise;
    }

    const refreshToken = this.getRefreshToken();
    
    if (!refreshToken) {
      console.error('No refresh token available');
      this.handleRefreshFailure();
      return null;
    }

    this.isRefreshing = true;
    
    this.refreshPromise = fetch('/api/refresh-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        refresh_token: refreshToken
      })
    })
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`Refresh failed: ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      // Store new tokens (data.expires_in is in seconds)
      this.setTokens(data.access_token, data.refresh_token, data.expires_in);
      console.log('Token refreshed successfully');
      
      this.isRefreshing = false;
      this.refreshPromise = null;
      
      return data.access_token;
    })
    .catch((error) => {
      console.error('Token refresh failed:', error);
      this.isRefreshing = false;
      this.refreshPromise = null;
      this.handleRefreshFailure();
      return null;
    });

    return this.refreshPromise;
  }

  /**
   * Handle refresh failure (logout user)
   */
  handleRefreshFailure() {
    console.log('Token refresh failed, logging out...');
    this.clearTokens();
    
    // Redirect to login page
    window.location.href = '/login';
  }

  /**
   * Clear all tokens and cancel scheduled refresh
   */
  clearTokens() {
    Cookies.remove(TOKEN_COOKIE_NAME);
    Cookies.remove(REFRESH_TOKEN_COOKIE_NAME);
    
    this.tokenExpiryTime = null;
    
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = null;
    }
    
    console.log('Tokens cleared from cookies');
  }

  /**
   * Get valid token (refresh if needed)
   */
  async getValidToken() {
    // If token is expired or about to expire, refresh it
    if (this.shouldRefreshToken()) {
      console.log('Token needs refresh, refreshing...');
      const newToken = await this.refreshToken();
      return newToken;
    }
    
    return this.getAccessToken();
  }

  /**
   * Initialize token manager on app load
   * Note: Since we don't store expiry in cookie, we can't recover it after page refresh
   * User will need to make an API call which will trigger refresh if token is expired
   */
  initialize() {
    const accessToken = this.getAccessToken();
    
    if (!accessToken) {
      console.log('No valid token found in cookies');
      return;
    }

    console.log('Token found in cookies. Will check validity on first API call.');
    
    // We can't know the exact expiry time after page refresh
    // But the token will be checked on first API call via getValidToken()
    // If it's expired (401), it will auto-refresh
  }
}

// Export singleton instance
const tokenManager = new TokenManager();
export default tokenManager;