// ============================================
// Dashboard Page (Protected)
// Location: /src/pages/Dashboard.jsx (React)
// ============================================
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, LogOut, Users, Settings, Server, 
  FileText, Menu, ChevronRight 
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import Card from '../components/ui/Card';
import FirewallRules from './FirewallRules';

const Dashboard = () => {
  const navigate = useNavigate();
  const { logout, isAuthenticated, getToken } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeSection, setActiveSection] = useState('overview');
  const [username, setUsername] = useState('Administrator');
  const [userRole, setUserRole] = useState('Loading...');

  // Protect this page - redirect if not authenticated
  useEffect(() => {
    if (!isAuthenticated()) {
      navigate('/login');
    } else {
      // Fetch user info
      fetchUserInfo();
    }
  }, [isAuthenticated, navigate]);

  const fetchUserInfo = async () => {
    try {
      const token = getToken();
      
      // Fetch username
      const usernameResponse = await apiClient.getUserName(token);
      if (usernameResponse.success) {
        setUsername(usernameResponse.username);
      }
      
      // Fetch user role
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

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const menuItems = [
    { id: 'overview', icon: Shield, label: 'Overview' },
    { id: 'users', icon: Users, label: 'User Management' },
    { id: 'firewall', icon: Settings, label: 'Firewall Rules' },
    { id: 'honeypots', icon: Server, label: 'Honeypots' },
    { id: 'logs', icon: FileText, label: 'System Logs' }
  ];

  const placeholders = {
    users: { title: 'User Management', desc: 'Manage system users and permissions' },
    firewall: { title: 'Firewall Rules', desc: 'Configure and manage firewall rules' },
    honeypots: { title: 'Honeypots', desc: 'Deploy and monitor honeypot systems' },
    logs: { title: 'System Logs', desc: 'View and analyze system logs' }
  };

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
                  {placeholders[item.id]?.desc}
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
                {[
                  { label: 'Active Rules', value: '24' },
                  { label: 'Honeypots', value: '3' },
                  { label: 'Blocked IPs', value: '156' },
                  { label: 'Alerts Today', value: '12' }
                ].map((stat) => (
                  <div key={stat.label} className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <p className="text-2xl font-bold text-orange-500">{stat.value}</p>
                    <p className="text-slate-400 text-sm">{stat.label}</p>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      );
    }

    // Firewall Rules page
    if (activeSection === 'firewall') {
      return <FirewallRules />;
    }

    // Placeholder pages for other sections
    const info = placeholders[activeSection];
    const Icon = menuItems.find(m => m.id === activeSection)?.icon || Shield;
    
    return (
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">{info?.title}</h2>
        <p className="text-slate-400 mb-8">{info?.desc}</p>
        <Card className="border-dashed border-2 border-slate-600 bg-slate-800/50">
          <div className="text-center py-12">
            <div className="bg-slate-700 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <Icon className="w-8 h-8 text-slate-400" />
            </div>
            <h3 className="text-lg font-medium text-slate-300 mb-2">Coming Soon</h3>
            <p className="text-slate-500">This section is under development.</p>
          </div>
        </Card>
      </div>
    );
  };

  return (
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
          <button onClick={() => setSidebarOpen(!sidebarOpen)} className="text-slate-400 hover:text-white">
            <Menu className="w-6 h-6" />
          </button>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-white font-medium">{username}</p>
              <div className="flex items-center justify-end gap-2 mt-1">
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${getRoleBadgeColor(
                    userRole
                  )}`}
                >
                  {userRole.toUpperCase()}
                </span>
              </div>
            </div>
            <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-red-600 rounded-full flex items-center justify-center">
              <span className="text-white font-bold text-sm">
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
  );
};

export default Dashboard;