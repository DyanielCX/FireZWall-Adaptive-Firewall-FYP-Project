// ============================================
// Honeypot Reports Page (Protected - Admin & CyberSec Only)
// Location: /src/pages/Honeypot.jsx
// ============================================
import { useState, useEffect } from 'react';
import { 
  Server, Search, Filter, X, AlertCircle, 
  Calendar, Shield, Globe, Activity, RefreshCw, Lock, ChevronLeft, ChevronRight 
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Alert from '../components/ui/Alert';
import HoneypotDetailsModal from '../components/HoneypotDetailsModal';

const Honeypot = () => {
  const { getToken } = useAuth();
  const [reports, setReports] = useState([]);
  const [filteredReports, setFilteredReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedReport, setSelectedReport] = useState(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [userRole, setUserRole] = useState(null);
  const [hasAccess, setHasAccess] = useState(null);
  
  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;
  
  // Filter states
  const [filters, setFilters] = useState({
    timestamp: '',
    event_type: '',
    ip: '',
    protocol: ''
  });

  useEffect(() => {
    checkAccess();
  }, []);

  const checkAccess = async () => {
    setLoading(true);
    try {
      const token = getToken();
      const response = await apiClient.getUserRole(token);
      
      if (response.success) {
        setUserRole(response.role);
        
        if (response.role !== 'admin' && response.role !== 'cybersec') {
          setHasAccess(false);
          setLoading(false);
          return;
        }
        
        setHasAccess(true);
        fetchReports();
      }
    } catch (err) {
      console.error('Error checking access:', err);
      setError('Failed to verify permissions');
      setHasAccess(false);
      setLoading(false);
    }
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

  useEffect(() => {
    applyFilters();
  }, [reports, filters]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filteredReports.length]);

  const fetchReports = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = getToken();
      const response = await apiClient.getHoneypots(token);
      
      if (response.success) {
        setReports(response.reports || []);
      } else {
        setError('Failed to fetch honeypot reports');
      }
    } catch (err) {
      console.error('Error fetching honeypot reports:', err);
      setError(err.message || 'Failed to fetch honeypot reports');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...reports];

    if (filters.timestamp.trim()) {
      filtered = filtered.filter(report => 
        report.timestamp.toLowerCase().includes(filters.timestamp.toLowerCase())
      );
    }

    if (filters.event_type.trim()) {
      filtered = filtered.filter(report => 
        report.event_type.toLowerCase().includes(filters.event_type.toLowerCase())
      );
    }

    if (filters.ip.trim()) {
      filtered = filtered.filter(report => 
        report.src_ip === filters.ip.trim()
      );
    }

    if (filters.protocol.trim()) {
      if (filters.protocol === '__NULL__') {
        // Filter for null protocol values
        filtered = filtered.filter(report => report.protocol === null);
      } else {
        // Filter for specific protocol string
        filtered = filtered.filter(report => 
          report.protocol && report.protocol.toLowerCase() === filters.protocol.toLowerCase()
        );
      }
    }

    setFilteredReports(filtered);
  };

  const handleFilterChange = (field, value) => {
    setFilters({ ...filters, [field]: value });
  };

  const clearFilters = () => {
    setFilters({
      timestamp: '',
      event_type: '',
      ip: '',
      protocol: ''
    });
  };

  const handleViewDetails = (report) => {
    setSelectedReport(report);
    setShowDetailsModal(true);
  };

  const getEventTypeBadge = (eventType) => {
    switch (eventType?.toLowerCase()) {
      case 'reconnaissance':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'brute-force attack':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'unauthorized access attempt':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getProtocolBadge = (protocol) => {
    // Handle null value (not string "null")
    if (protocol === null || protocol === undefined) {
      return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
    
    switch (protocol.toLowerCase()) {
      case 'ssh':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'telnet':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const hasActiveFilters = () => {
    return Object.values(filters).some(value => value.trim() !== '');
  };

  // Pagination calculations
  const totalPages = Math.ceil(filteredReports.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentReports = filteredReports.slice(startIndex, endIndex);

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

  // Show loading while checking access
  if (loading && hasAccess === null) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-orange-500 animate-spin" />
        <span className="ml-3 text-slate-300">Verifying permissions...</span>
      </div>
    );
  }

  // Show access denied page
  if (hasAccess === false) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Card className="w-full max-w-md">
          <div className="text-center py-8">
            <div className="bg-red-500/20 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6">
              <Lock className="w-10 h-10 text-red-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-3">Access Denied</h3>
            <p className="text-slate-300 mb-2">
              You don't have permission to access Honeypot Reports.
            </p>
            <p className="text-slate-400 text-sm mb-6">
              Only <span className="text-red-400 font-medium">Admin</span> and{' '}
              <span className="text-purple-400 font-medium">CyberSec</span> roles can view honeypot reports.
            </p>
            {userRole && (
              <div className="bg-slate-700/50 rounded-lg p-4 mb-6">
                <p className="text-slate-400 text-sm mb-1">Your current role:</p>
                <span
                  className={`inline-flex items-center px-3 py-1.5 rounded-md text-sm font-medium border ${getRoleBadgeColor(
                    userRole
                  )}`}
                >
                  {userRole.toUpperCase()}
                </span>
              </div>
            )}
            <div className="flex flex-col gap-3">
              <Button
                variant="secondary"
                onClick={() => window.location.reload()}
                className="flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Try Again
              </Button>
              <Button
                variant="outline"
                onClick={() => window.history.back()}
                className="flex items-center justify-center gap-2"
              >
                Go Back
              </Button>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Honeypot Reports</h2>
          <p className="text-slate-400">
            Monitor and analyze honeypot security events
          </p>
        </div>
        <div className="flex gap-3">
          <Button
            variant="secondary"
            onClick={fetchReports}
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
              Filter Reports
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

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
              <p className="text-xs text-slate-500 mt-1">Format: YYYY-MM-DD or YYYY-MM</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <Shield className="w-4 h-4 inline mr-1" />
                Event Type
              </label>
              <select
                value={filters.event_type}
                onChange={(e) => handleFilterChange('event_type', e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-700 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              >
                <option value="">All Types</option>
                <option value="reconnaissance">Reconnaissance</option>
                <option value="brute-force attack">Brute-Force Attack</option>
                <option value="unauthorized access attempt">Unauthorized Access Attempt</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <Globe className="w-4 h-4 inline mr-1" />
                Source IP
              </label>
              <Input
                type="text"
                placeholder="e.g., 192.168.1.1"
                value={filters.ip}
                onChange={(e) => handleFilterChange('ip', e.target.value)}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                <Server className="w-4 h-4 inline mr-1" />
                Protocol
              </label>
              <select
                value={filters.protocol}
                onChange={(e) => handleFilterChange('protocol', e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-700 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              >
                <option value="">All Protocols</option>
                <option value="ssh">SSH</option>
                <option value="telnet">Telnet</option>
                <option value="__NULL__">N/A</option>
              </select>
            </div>
          </div>
        </Card>
      )}

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Total Reports</p>
              <p className="text-2xl font-bold text-white mt-1">{reports.length}</p>
            </div>
            <div className="bg-orange-500/20 p-3 rounded-lg">
              <Server className="w-6 h-6 text-orange-500" />
            </div>
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Filtered Results</p>
              <p className="text-2xl font-bold text-white mt-1">{filteredReports.length}</p>
            </div>
            <div className="bg-blue-500/20 p-3 rounded-lg">
              <Search className="w-6 h-6 text-blue-500" />
            </div>
          </div>
        </Card>

        <Card>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Unique IPs</p>
              <p className="text-2xl font-bold text-white mt-1">
                {new Set(reports.map(r => r.src_ip)).size}
              </p>
            </div>
            <div className="bg-purple-500/20 p-3 rounded-lg">
              <Globe className="w-6 h-6 text-purple-500" />
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

      {/* Reports Table */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">
            Security Events
          </h3>
          <span className="text-sm text-slate-400">
            Showing {startIndex + 1}-{Math.min(endIndex, filteredReports.length)} of {filteredReports.length} reports
          </span>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500 mx-auto"></div>
            <p className="text-slate-400 mt-4">Loading reports...</p>
          </div>
        ) : filteredReports.length === 0 ? (
          <div className="text-center py-12">
            <Server className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">
              {reports.length === 0 
                ? 'No honeypot reports found' 
                : 'No reports match the current filters'}
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
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Event Type</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Protocol</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Source IP</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {currentReports.map((report) => (
                    <tr 
                      key={report.id} 
                      className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors"
                    >
                      <td className="py-3 px-4 text-slate-300 font-mono text-sm">
                        #{report.id}
                      </td>
                      <td className="py-3 px-4 text-slate-300 text-sm">
                        {report.timestamp}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getEventTypeBadge(report.event_type)}`}>
                          {report.event_type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getProtocolBadge(report.protocol)}`}>
                          {report.protocol ? report.protocol.toUpperCase() : 'N/A'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 font-mono text-sm">
                        {report.src_ip}
                      </td>
                      <td className="py-3 px-4">
                        <Button
                          variant="outline"
                          onClick={() => handleViewDetails(report)}
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
                      // Show first page, last page, current page, and pages around current
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
      {showDetailsModal && selectedReport && (
        <HoneypotDetailsModal
          isOpen={showDetailsModal}
          onClose={() => {
            setShowDetailsModal(false);
            setSelectedReport(null);
          }}
          report={selectedReport}
        />
      )}
    </div>
  );
};

export default Honeypot;