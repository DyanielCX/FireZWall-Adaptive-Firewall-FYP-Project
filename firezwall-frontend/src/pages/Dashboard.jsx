// ============================================
// Dashboard Page (Protected)
// Location: /src/pages/Dashboard.jsx
// ============================================
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, LogOut, Users, Settings, Server, 
  FileText, Menu, ChevronRight, GraduationCap 
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import Card from '../components/ui/Card';
import FirewallRules from './FirewallRules';
import UserManagement from './UserManagement';
import Honeypot from './Honeypot';
import SystemLogs from './SystemLogs';
import LabDashboard from './lab/LabDashboard';

const Dashboard = () => {
  const navigate = useNavigate();
  const { logout, isAuthenticated, getToken } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeSection, setActiveSection] = useState('overview');
  const [username, setUsername] = useState('Administrator');
  const [userRole, setUserRole] = useState('Loading...');
  const [mode, setMode] = useState('real-system'); // 'real-system' or 'lab'
  
  // Quick Stats data
  const [stats, setStats] = useState({
    activeRules: 0,
    honeypots: null,
    blockedIPs: null,
    alertsToday: 0,
    loading: true
  });

  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
    } else {
      fetchUserInfo();
    }
  }, [isAuthenticated, navigate]);

  // Fetch stats after user role is determined
  useEffect(() => {
    if (userRole && userRole !== 'Loading...') {
      fetchQuickStats();
    }
  }, [userRole]);

  const fetchUserInfo = async () => {
    try {
      const token = getToken();
      
      const usernameResponse = await apiClient.getUserName(token);
      if (usernameResponse.success) {
        setUsername(usernameResponse.username);
      }
      
      const roleResponse = await apiClient.getUserRole(token);
      if (roleResponse.success) {
        setUserRole(roleResponse.role);
      }
    } catch (error) {
      console.error('Error fetching user info:', error);
      setUsername('User');
      setUserRole('Unknown');
    }
  };

  const fetchQuickStats = async () => {
    try {
      const token = getToken();
      
      // Fetch firewall rules and logs for all users
      const [rulesResponse, logsResponse] = await Promise.all([
        apiClient.getFirewallRules(token),
        apiClient.getSystemLogs(token, {})
      ]);

      // Count active firewall rules
      const activeRules = rulesResponse.success ? (rulesResponse['Firewall-Rules'] || []).length : 0;
      
      // Count ERROR/WARNING logs from today
      const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
      const alertsToday = logsResponse.success
        ? (logsResponse.logs || []).filter(log => 
            (log.level === 'ERROR' || log.level === 'WARNING') && 
            log.timestamp.startsWith(today)
          ).length
        : 0;

      // Only fetch honeypot data for admin and cybersec roles
      let honeypots = null;
      let blockedIPs = null;
      
      if (userRole === 'admin' || userRole === 'cybersec') {
        try {
          const honeypotResponse = await apiClient.getHoneypots(token);
          
          if (honeypotResponse.success) {
            honeypots = (honeypotResponse.reports || []).length;
            blockedIPs = new Set((honeypotResponse.reports || []).map(r => r.src_ip)).size;
          }
        } catch (error) {
          // If honeypot access fails, just set to null (will be hidden in UI)
          console.log('No access to honeypot data');
        }
      }

      setStats({
        activeRules,
        honeypots,
        blockedIPs,
        alertsToday,
        loading: false
      });
    } catch (error) {
      console.error('Error fetching quick stats:', error);
      setStats(prev => ({ ...prev, loading: false }));
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const menuItems = [
    { id: 'overview', icon: Shield, label: 'Dashboard' },
    { id: 'users', icon: Users, label: 'User Management' },
    { id: 'firewall', icon: Settings, label: 'Firewall Rules' },
    { id: 'honeypots', icon: Server, label: 'Honeypots' },
    { id: 'logs', icon: FileText, label: 'System Logs' }
  ];

  const getRoleBadgeColor = (role) => {
    switch (role?.toLowerCase()) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'dev':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'cybersec':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'user':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const renderContent = () => {
    if (activeSection === 'overview') {
      return (
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">
            Welcome to FireZWall Management Console
          </h2>
          <p className="text-slate-400 mb-8">
            Monitor and manage your firewall system from this dashboard.
          </p>
          
          {/* Feature Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {menuItems.slice(1).map((item) => (
              <Card 
                key={item.id} 
                hoverable 
                onClick={() => setActiveSection(item.id)}
              >
                <div className="bg-gradient-to-br from-orange-500/20 to-red-600/20 w-12 h-12 rounded-lg flex items-center justify-center mb-4">
                  <item.icon className="w-6 h-6 text-orange-500" />
                </div>
                <h3 className="text-lg font-semibold text-white mb-1">
                  {item.label}
                </h3>
                <p className="text-slate-400 text-sm">
                  {item.id === 'users' && 'Manage system users and permissions'}
                  {item.id === 'firewall' && 'Configure and manage firewall rules'}
                  {item.id === 'honeypots' && 'Deploy and monitor honeypot systems'}
                  {item.id === 'logs' && 'View and analyze system logs'}
                </p>
                <div className="mt-4 flex items-center text-orange-500 text-sm font-medium">
                  Open <ChevronRight className="w-4 h-4 ml-1" />
                </div>
              </Card>
            ))}
          </div>
          
          {/* Status Cards */}
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <h3 className="text-lg font-semibold text-white mb-4">System Status</h3>
              <div className="space-y-3">
                {['Firewall Service', 'Honeypot Service', 'Log Collector'].map((service) => (
                  <div key={service} className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg">
                    <span className="text-slate-300">{service}</span>
                    <span className="flex items-center gap-2 text-green-400 text-sm">
                      <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                      Active
                    </span>
                  </div>
                ))}
              </div>
            </Card>
            
            <Card>
              <h3 className="text-lg font-semibold text-white mb-4">Quick Stats</h3>
              <div className="grid grid-cols-2 gap-4">
                {/* Active Rules - show for all users */}
                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                  <p className="text-2xl font-bold text-orange-500">
                    {stats.loading ? '...' : stats.activeRules}
                  </p>
                  <p className="text-slate-400 text-sm">Active Rules</p>
                </div>

                {/* Honeypot Reports - only show for admin/cybersec */}
                {(userRole === 'admin' || userRole === 'cybersec') && (
                  <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <p className="text-2xl font-bold text-orange-500">
                      {stats.loading ? '...' : (stats.honeypots ?? 0)}
                    </p>
                    <p className="text-slate-400 text-sm">Honeypot Reports</p>
                  </div>
                )}

                {/* Blocked IPs - only show for admin/cybersec */}
                {(userRole === 'admin' || userRole === 'cybersec') && (
                  <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <p className="text-2xl font-bold text-orange-500">
                      {stats.loading ? '...' : (stats.blockedIPs ?? 0)}
                    </p>
                    <p className="text-slate-400 text-sm">Blocked IPs</p>
                  </div>
                )}

                {/* Alerts Today - show for all users */}
                <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                  <p className="text-2xl font-bold text-orange-500">
                    {stats.loading ? '...' : stats.alertsToday}
                  </p>
                  <p className="text-slate-400 text-sm">Alerts Today</p>
                </div>
              </div>
            </Card>
          </div>
        </div>
      );
    }

    // User Management Page
    if (activeSection === 'users') {
      return <UserManagement />;
    }
    
    // Firewall Rules page
    if (activeSection === 'firewall') {
      return <FirewallRules />;
    }

    // Honeypot page
    if (activeSection === 'honeypots') {
      return <Honeypot />;
    }

    // SystemLogs page
    if (activeSection === 'logs') {
      return <SystemLogs />;
    }

    return null;
  };

  return (
    <>
      {/* Lab Mode */}
      {mode === 'lab' && (
        <LabDashboard 
          onSwitchToRealSystem={() => setMode('real-system')}
          username={username}
          userRole={userRole}
        />
      )}

      {/* Real System Mode */}
      {mode === 'real-system' && (
        <div className="min-h-screen bg-slate-900 flex">
          {/* Sidebar */}
          <aside className={`${sidebarOpen ? 'w-64' : 'w-20'} bg-slate-800 border-r border-slate-700 transition-all duration-300 flex flex-col`}>
        <div className="p-4 border-b border-slate-700 flex items-center gap-3">
          <div className="bg-gradient-to-br from-orange-500 to-red-600 p-2 rounded-lg flex-shrink-0">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {sidebarOpen && <span className="font-bold text-white">FireZWall</span>}
        </div>
        
        <nav className="flex-1 p-4">
          <ul className="space-y-2">
            {menuItems.map((item) => (
              <li key={item.id}>
                <button
                  onClick={() => setActiveSection(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                    activeSection === item.id 
                      ? 'bg-gradient-to-r from-orange-500/20 to-red-600/20 text-orange-500 border border-orange-500/30' 
                      : 'text-slate-400 hover:bg-slate-700 hover:text-white'
                  }`}
                >
                  <item.icon className="w-5 h-5 flex-shrink-0" />
                  {sidebarOpen && <span>{item.label}</span>}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        
        <div className="p-4 border-t border-slate-700">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-5 h-5 flex-shrink-0" />
            {sidebarOpen && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <header className="bg-slate-800 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-slate-400 hover:text-white transition-colors"
            >
              <Menu className="w-6 h-6" />
            </button>
            
            {/* Mode Switch Button */}
            <button
              onClick={() => setMode('lab')}
              className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white transition-all flex items-center gap-2 text-sm border border-slate-600"
            >
              <GraduationCap className="w-4 h-4" />
              <span>Switch to Lab Mode</span>
            </button>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium text-white">{username}</p>
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${getRoleBadgeColor(userRole)}`}>
                {userRole}
              </span>
            </div>
            <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-red-600 rounded-full flex items-center justify-center">
              <span className="text-white font-bold">
                {username.charAt(0).toUpperCase()}
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-6 overflow-auto">
          {renderContent()}
        </main>
      </div>
        </div>
      )}
    </>
  );
};

export default Dashboard;