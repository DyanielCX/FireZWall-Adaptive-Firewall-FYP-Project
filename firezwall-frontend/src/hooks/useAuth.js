// ============================================
// Auth Context
// Location: /src/context/AuthContext.js
// ============================================
const AuthContext = createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = Cookies.get('access_token');
    if (token) setUser({ token });
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    const data = await apiClient.login(username, password);
    Cookies.set('access_token', data.access_token);
    Cookies.set('refresh_token', data.refresh_token);
    setUser({ token: data.access_token });
    return data;
  };

  const logout = () => {
    Cookies.remove('access_token');
    Cookies.remove('refresh_token');
    setUser(null);
  };

  const isAuthenticated = () => !!Cookies.get('access_token');

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => useContext(AuthContext);