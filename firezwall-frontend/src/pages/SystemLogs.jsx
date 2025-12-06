// ============================================
// System Logs Page (Protected - All Roles)
// Location: /src/pages/SystemLogs.jsx
// ============================================
import { useState, useEffect } from 'react';
import { 
  FileText, Search, Filter, X, AlertCircle, 
  Calendar, Shield, Globe, Activity, RefreshCw, ChevronLeft, ChevronRight,
  User, Server
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Alert from '../components/ui/Alert';
import SystemLogDetailsModal from '../components/SystemLogDetailsModal';

const SystemLogs = () => {
  const { getToken } = useAuth();
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [userRole, setUserRole] = useState(null);
  
  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;
  
  // Filter states
  const [filters, setFilters] = useState({
    timestamp: '',
    level: '',
    module: '',
    username: '',
    endpoint: ''
  });

  useEffect(() => {
    fetchUserRole();
    fetchLogs();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [logs, filters]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filteredLogs.length]);

  const fetchUserRole = async () => {
    try {
      const token = getToken();
      const response = await apiClient.getUserRole(token);
      
      if (response.success) {
        setUserRole(response.role);
      }
    } catch (err) {
      console.error('Error fetching user role:', err);
    }
  };

  const fetchLogs = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = getToken();
      const response = await apiClient.getSystemLogs(token, {});
      
      if (response.success) {
        // Sort logs by timestamp descending (latest first)
        const sortedLogs = (response.logs || []).sort((a, b) => {
          return new Date(b.timestamp) - new Date(a.timestamp);
        });
        setLogs(sortedLogs);
      } else {
        setError('Failed to fetch system logs');
      }
    } catch (err) {
      console.error('Error fetching system logs:', err);
      setError(err.message || 'Failed to fetch system logs');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...logs];

    if (filters.timestamp.trim()) {
      filtered = filtered.filter(log => 
        log.timestamp.toLowerCase().includes(filters.timestamp.toLowerCase())
      );
    }

    if (filters.level.trim()) {
      filtered = filtered.filter(log => 
        log.level.toLowerCase() === filters.level.toLowerCase()
      );
    }

    if (filters.module.trim()) {
      filtered = filtered.filter(log => 
        log.module.toLowerCase() === filters.module.toLowerCase()
      );
    }

    if (filters.username.trim()) {
      filtered = filtered.filter(log => 
        log.username && log.username.toLowerCase().includes(filters.username.toLowerCase())
      );
    }

    if (filters.endpoint.trim()) {
      filtered = filtered.filter(log => 
        log.endpoint && log.endpoint.toLowerCase().includes(filters.endpoint.toLowerCase())
      );
    }

    setFilteredLogs(filtered);
  };

  const handleFilterChange = (field, value) => {
    setFilters({ ...filters, [field]: value });
  };

  const clearFilters = () => {
    setFilters({
      timestamp: '',
      level: '',
      module: '',
      username: '',
      endpoint: ''
    });
  };

  const handleViewDetails = (log) => {
    setSelectedLog(log);
    setShowDetailsModal(true);
  };

  const getLevelBadge = (level) => {
    switch (level?.toUpperCase()) {
      case 'INFO':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'WARNING':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'ERROR':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getModuleBadge = (module) => {
    switch (module?.toLowerCase()) {
      case 'auth':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'firewall':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'honeypot':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'syslog':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const hasActiveFilters = () => {
    return Object.values(filters).some(value => value.trim() !== '');
  };

  // Pagination calculations
  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentLogs = filteredLogs.slice(startIndex, endIndex);

  const goToPage = (page) => {
    setCurrentPage(page);
  };

  const goToPreviousPage = () => {
    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };

  const goToNextPage = () => {
    if (currentPage < totalPages) {
      setCurrentPage(currentPage + 1);
    }
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">System Logs</h2>
          <p className="text-slate-400">
            View and analyze system logs
          </p>
        </div>
        <div className="flex gap-3">
          <Button
            variant="secondary"
            onClick={fetchLogs}
            disabled={loading}
            className="flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
          <Button
            variant={showFilters ? 'primary' : 'outline'}
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2"
          >
            <Filter className="w-4 h-4" />
            {showFilters ? 'Hide Filters' : 'Show Filters'}
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <Alert variant="error" className="mb-4">
          <AlertCircle className="w-5 h-5" />
          <div>
            <p className="font-medium">Error</p>
            <p className="text-sm">{error}</p>
          </div>
        </Alert>
      )}

      {/* Filter Section */}
      {showFilters && (
        <Card className="mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Filter className="w-5 h-5 text-orange-500" />
              Filter Logs
            </h3>
            {hasActiveFilters() && (
              <Button
                variant="outline"
                onClick={clearFilters}
                className="flex items-center gap-2 text-sm"
              >
                <X className="w-4 h-4" />
                Clear All
              </Button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <Calendar className="w-4 h-4 inline mr-1" />
                Timestamp
              </label>
              <Input
                type="text"
                placeholder="YYYY-MM-DD"
                value={filters.timestamp}
                onChange={(e) => handleFilterChange('timestamp', e.target.value)}
              />
              <p className="text-xs text-slate-500 mt-1">Format: YYYY-MM-DD or YYYY-MM or YYYY</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <AlertCircle className="w-4 h-4 inline mr-1" />
                Level
              </label>
              <select
                value={filters.level}
                onChange={(e) => handleFilterChange('level', e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-700 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              >
                <option value="">All Levels</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <Shield className="w-4 h-4 inline mr-1" />
                Module
              </label>
              <select
                value={filters.module}
                onChange={(e) => handleFilterChange('module', e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-700 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              >
                <option value="">All Modules</option>
                <option value="auth">Auth</option>
                <option value="firewall">Firewall</option>
                <option value="honeypot">Honeypot</option>
                <option value="syslog">Syslog</option>
              </select>
            </div>

            {/* Username filter - only show for admin */}
            {userRole === 'admin' && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  <User className="w-4 h-4 inline mr-1" />
                  Username
                </label>
                <Input
                  type="text"
                  placeholder="e.g., admin"
                  value={filters.username}
                  onChange={(e) => handleFilterChange('username', e.target.value)}
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <Server className="w-4 h-4 inline mr-1" />
                Endpoint
              </label>
              <Input
                type="text"
                placeholder="e.g., /api/login"
                value={filters.endpoint}
                onChange={(e) => handleFilterChange('endpoint', e.target.value)}
              />
            </div>
          </div>
        </Card>
      )}

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Total Logs</p>
              <p className="text-2xl font-bold text-white mt-1">{logs.length}</p>
            </div>
            <div className="bg-orange-500/20 p-3 rounded-lg">
              <FileText className="w-6 h-6 text-orange-500" />
            </div>
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Filtered Results</p>
              <p className="text-2xl font-bold text-white mt-1">{filteredLogs.length}</p>
            </div>
            <div className="bg-blue-500/20 p-3 rounded-lg">
              <Search className="w-6 h-6 text-blue-500" />
            </div>
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Errors</p>
              <p className="text-2xl font-bold text-white mt-1">
                {logs.filter(l => l.level === 'ERROR').length}
              </p>
            </div>
            <div className="bg-red-500/20 p-3 rounded-lg">
              <AlertCircle className="w-6 h-6 text-red-500" />
            </div>
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Active Filters</p>
              <p className="text-2xl font-bold text-white mt-1">
                {Object.values(filters).filter(v => v.trim() !== '').length}
              </p>
            </div>
            <div className="bg-green-500/20 p-3 rounded-lg">
              <Filter className="w-6 h-6 text-green-500" />
            </div>
          </div>
        </Card>
      </div>

      {/* Logs Table */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">
            System Events
          </h3>
          <span className="text-sm text-slate-400">
            Showing {startIndex + 1}-{Math.min(endIndex, filteredLogs.length)} of {filteredLogs.length} logs
          </span>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500 mx-auto"></div>
            <p className="text-slate-400 mt-4">Loading logs...</p>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">
              {logs.length === 0 
                ? 'No system logs found' 
                : 'No logs match the current filters'}
            </p>
            {hasActiveFilters() && (
              <Button
                variant="outline"
                onClick={clearFilters}
                className="mt-4"
              >
                Clear Filters
              </Button>
            )}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">ID</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Timestamp</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Level</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Event Type</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Module</th>
                    {userRole === 'admin' && (
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Username</th>
                    )}
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Endpoint</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {currentLogs.map((log) => (
                    <tr 
                      key={log.id} 
                      className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors"
                    >
                      <td className="py-3 px-4 text-slate-300 font-mono text-sm">
                        #{log.id}
                      </td>
                      <td className="py-3 px-4 text-slate-300 text-sm">
                        {log.timestamp}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getLevelBadge(log.level)}`}>
                          {log.level}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 text-sm">
                        {log.event_type}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getModuleBadge(log.module)}`}>
                          {log.module}
                        </span>
                      </td>
                      {userRole === 'admin' && (
                        <td className="py-3 px-4 text-slate-300 text-sm">
                          {log.username || <span className="text-slate-500">N/A</span>}
                        </td>
                      )}
                      <td className="py-3 px-4 text-slate-300 text-sm font-mono">
                        {log.endpoint || <span className="text-slate-500">N/A</span>}
                      </td>
                      <td className="py-3 px-4">
                        <Button
                          variant="outline"
                          onClick={() => handleViewDetails(log)}
                          className="text-sm px-3 py-1"
                        >
                          View Details
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-6 pt-4 border-t border-slate-700">
                <div className="text-sm text-slate-400">
                  Page {currentPage} of {totalPages}
                </div>
                
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    onClick={goToPreviousPage}
                    disabled={currentPage === 1}
                    className="flex items-center gap-1"
                  >
                    <ChevronLeft className="w-4 h-4" />
                    Previous
                  </Button>

                  <div className="flex gap-1">
                    {[...Array(totalPages)].map((_, index) => {
                      const pageNumber = index + 1;
                      if (
                        pageNumber === 1 ||
                        pageNumber === totalPages ||
                        (pageNumber >= currentPage - 1 && pageNumber <= currentPage + 1)
                      ) {
                        return (
                          <button
                            key={pageNumber}
                            onClick={() => goToPage(pageNumber)}
                            className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
                              currentPage === pageNumber
                                ? 'bg-orange-500 text-white'
                                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                            }`}
                          >
                            {pageNumber}
                          </button>
                        );
                      } else if (
                        pageNumber === currentPage - 2 ||
                        pageNumber === currentPage + 2
                      ) {
                        return (
                          <span key={pageNumber} className="px-2 text-slate-500">
                            ...
                          </span>
                        );
                      }
                      return null;
                    })}
                  </div>

                  <Button
                    variant="outline"
                    onClick={goToNextPage}
                    disabled={currentPage === totalPages}
                    className="flex items-center gap-1"
                  >
                    Next
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>

      {/* Details Modal */}
      {showDetailsModal && selectedLog && (
        <SystemLogDetailsModal
          isOpen={showDetailsModal}
          onClose={() => {
            setShowDetailsModal(false);
            setSelectedLog(null);
          }}
          log={selectedLog}
        />
      )}
    </div>
  );
};

export default SystemLogs;