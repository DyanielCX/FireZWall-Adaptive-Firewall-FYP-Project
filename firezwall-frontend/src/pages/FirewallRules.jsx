// ============================================
// Firewall Rules Page (Protected)
// Location: /src/pages/FirewallRules.jsx
// ============================================

import { useState, useEffect } from 'react';
import { Shield, Plus, Check, X, RefreshCw, AlertCircle, Lock, Trash2, ChevronLeft, ChevronRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Alert from '../components/ui/Alert';
import AddFirewallRuleModal from '../components/AddFirewallRuleModal';

const FirewallRules = () => {
  const { getToken } = useAuth();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [userRole, setUserRole] = useState(null);
  const [checkingRole, setCheckingRole] = useState(false);
  const [showAccessDenied_AddRules, setShowAccessDenied_AddRules] = useState(false);
  const [showAccessDenied_DltRules, setShowAccessDenied_DltRules] = useState(false);
  
  // Pagination states
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;
  
  // Delete confirmation modal
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [ruleToDelete, setRuleToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  // Fetch firewall rules on component mount
  useEffect(() => {
    fetchRules();
    fetchUserRole();
  }, []);

  // Reset to page 1 when rules change
  useEffect(() => {
    setCurrentPage(1);
  }, [rules.length]);

  const fetchRules = async () => {
    setLoading(true);
    setError('');
    
    try {
      const token = getToken();
      const response = await apiClient.getFirewallRules(token);
      
      if (response.success) {
        setRules(response['Firewall-Rules'] || []);
      } else {
        setError('Failed to load firewall rules');
      }
    } catch (err) {
      console.error('Error fetching firewall rules:', err);
      setError(err.message || 'Failed to fetch firewall rules');
    } finally {
      setLoading(false);
    }
  };

  const fetchUserRole = async () => {
    try {
      const token = getToken();
      const response = await apiClient.getUserRole(token);
      
      if (response.success) {
        setUserRole(response.role);
        console.log('User role:', response.role);
      }
    } catch (err) {
      console.error('Error fetching user role:', err);
    }
  };

  const handleAddRule = async () => {
    setCheckingRole(true);
    
    try {
      const token = getToken();
      const response = await apiClient.getUserRole(token);
      
      if (response.success) {
        const role = response.role;
        
        // Check if user has permission (admin, dev, or cybersec)
        if (role === 'admin' || role === 'dev' || role === 'cybersec') {
          setShowAddModal(true);
        } else {
          setShowAccessDenied_AddRules(true);
        }
      }
    } catch (err) {
      console.error('Error checking user role:', err);
      setError('Failed to verify permissions');
    } finally {
      setCheckingRole(false);
    }
  };

  const handleSubmitRule = async (ruleData) => {
    setSubmitting(true);
    setError('');
    setSuccess('');

    try {
      const token = getToken();
      const response = await apiClient.addFirewallRule(token, ruleData);
      
      console.log('Rule added successfully:', response);
      setSuccess('Firewall rule added successfully!');
      
      // Refresh the rules list
      await fetchRules();
      
      // Close modal
      setShowAddModal(false);
      
      // Clear success message after 3 seconds
      setTimeout(() => setSuccess(''), 3000);
      
    } catch (err) {
      console.error('Error adding firewall rule:', err);
      throw err; // Re-throw to let modal handle the error
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteClick = async (rule) => {
    // Check role before showing delete confirmation
    setCheckingRole(true);
    
    try {
      const token = getToken();
      const response = await apiClient.getUserRole(token);
      
      if (response.success) {
        const role = response.role;
        
        // Check if user has permission (admin, dev, or cybersec)
        if (role === 'admin') {
          setRuleToDelete(rule);
          setShowDeleteModal(true);
        } else {
          setShowAccessDenied_DltRules(true);
        }
      }
    } catch (err) {
      console.error('Error checking user role:', err);
      setError('Failed to verify permissions');
    } finally {
      setCheckingRole(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!ruleToDelete) return;
  
    setDeleting(true);
    setError('');
    setSuccess('');
  
    try {
      const token = getToken();
      
      // Prepare delete data object (like add rule)
      const ruleData = {
        action: ruleToDelete.action,
        port: ruleToDelete.port,
        protocol: ruleToDelete.protocol,
        direction: ruleToDelete.direction,
        ipv4: ruleToDelete.ipv4,
        ipv6: ruleToDelete.ipv6,
      };
  
      // Add source only if it's not "Anywhere"
      if (ruleToDelete.source && ruleToDelete.source.toLowerCase() !== 'anywhere') {
        ruleData.source = ruleToDelete.source;
      }
  
      console.log('Deleting rule with data:', ruleData);
  
      // Call smart delete function
      await apiClient.deleteFirewallRule(token, ruleData);
  
      setSuccess('Firewall rule deleted successfully!');
      
      // Refresh rules list
      await fetchRules();
      
      // Close modal
      setShowDeleteModal(false);
      setRuleToDelete(null);
      
      // Clear success message after 3 seconds
      setTimeout(() => setSuccess(''), 3000);
  
    } catch (err) {
      console.error('Error deleting firewall rule:', err);
      setError(err.message || 'Failed to delete firewall rule');
    } finally {
      setDeleting(false);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteModal(false);
    setRuleToDelete(null);
  };

  const renderBooleanIcon = (value) => {
    return value ? (
      <Check className="w-5 h-5 text-green-400 mx-auto" />
    ) : (
      <X className="w-5 h-5 text-red-400 mx-auto" />
    );
  };

  const getActionBadgeColor = (action) => {
    switch (action.toUpperCase()) {
      case 'ALLOW':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'DENY':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'REJECT':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  // Pagination calculations
  const totalPages = Math.ceil(rules.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentRules = rules.slice(startIndex, endIndex);

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
          <h2 className="text-2xl font-bold text-white mb-2">Firewall Rules</h2>
          <p className="text-slate-400">
            Configure and manage firewall rules
          </p>
        </div>
        <div className="flex gap-3">
          <Button
            variant="secondary"
            onClick={fetchRules}
            className="flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
          <Button
            onClick={handleAddRule}
            className="flex items-center gap-2"
            disabled={checkingRole}
          >
            {checkingRole ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Checking...
              </>
            ) : (
              <>
                <Plus className="w-4 h-4" />
                Add Rule
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mb-4">
          <Alert
            type="error"
            message={error}
            onClose={() => setError('')}
          />
        </div>
      )}

      {/* Success Alert */}
      {success && (
        <div className="mb-4">
          <Alert
            type="success"
            message={success}
            onClose={() => setSuccess('')}
          />
        </div>
      )}

      {/* Rules Table */}
      <Card className="overflow-hidden p-0">
        {loading ? (
          <div className="text-center py-12">
            <RefreshCw className="w-8 h-8 text-orange-500 animate-spin mx-auto" />
            <p className="text-slate-400 mt-4">Loading firewall rules...</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-slate-700/50 border-b border-slate-600">
                    <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Action
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Port
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Protocol
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Direction
                    </th>
                    <th className="px-6 py-4 text-center text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      IPv4
                    </th>
                    <th className="px-6 py-4 text-center text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      IPv6
                    </th>
                    <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Source
                    </th>
                    <th className="px-6 py-4 text-center text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {rules.length === 0 ? (
                    <tr>
                      <td colSpan="8" className="px-6 py-12 text-center">
                        <Shield className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                        <p className="text-slate-400 text-sm">
                          No firewall rules configured
                        </p>
                        {(userRole === 'admin' || userRole === 'dev' || userRole === 'cybersec') && (
                          <Button
                            variant="outline"
                            onClick={handleAddRule}
                            className="mt-4"
                          >
                            Add Your First Rule
                          </Button>
                        )}
                      </td>
                    </tr>
                  ) : (
                    currentRules.map((rule, index) => (
                      <tr
                        key={index}
                        className="hover:bg-slate-700/30 transition-colors"
                      >
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium border ${getActionBadgeColor(
                              rule.action
                            )}`}
                          >
                            {rule.action}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                          {rule.port}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="inline-flex items-center px-2 py-1 rounded bg-slate-700 text-xs font-mono text-slate-300">
                            {rule.protocol}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                              rule.direction === 'IN'
                                ? 'bg-blue-500/20 text-blue-400'
                                : 'bg-purple-500/20 text-purple-400'
                            }`}
                          >
                            {rule.direction}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          {renderBooleanIcon(rule.ipv4)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          {renderBooleanIcon(rule.ipv6)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                          {rule.source}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          <button
                            onClick={() => handleDeleteClick(rule)}
                            className="inline-flex items-center justify-center w-8 h-8 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors"
                            title="Delete rule"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-6 py-4 border-t border-slate-700">
                <div className="text-sm text-slate-400">
                  Showing {startIndex + 1}-{Math.min(endIndex, rules.length)} of {rules.length} rules
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

      {/* Add Rule Modal */}
      {showAddModal && (
        <AddFirewallRuleModal
          isOpen={showAddModal}
          onClose={() => setShowAddModal(false)}
          onSubmit={handleSubmitRule}
          loading={submitting}
        />
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && ruleToDelete && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <div className="text-center py-6">
              <div className="bg-red-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <Trash2 className="w-8 h-8 text-red-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Delete Firewall Rule</h3>
              <p className="text-slate-300 mb-4">
                Are you sure you want to delete this firewall rule?
              </p>
              
              {/* Rule Details */}
              <div className="bg-slate-700/50 rounded-lg p-4 mb-6 text-left">
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <span className="text-slate-400">Action:</span>
                  <span className="text-white font-medium">{ruleToDelete.action}</span>
                  
                  <span className="text-slate-400">Port:</span>
                  <span className="text-white font-medium">{ruleToDelete.port}</span>
                  
                  <span className="text-slate-400">Protocol:</span>
                  <span className="text-white font-medium">{ruleToDelete.protocol}</span>
                  
                  <span className="text-slate-400">Direction:</span>
                  <span className="text-white font-medium">{ruleToDelete.direction}</span>
                  
                  <span className="text-slate-400">Source:</span>
                  <span className="text-white font-medium">{ruleToDelete.source}</span>
                </div>
              </div>

              <p className="text-red-400 text-sm mb-6">
                This action cannot be undone.
              </p>

              <div className="flex gap-3">
                <Button
                  variant="secondary"
                  onClick={handleCancelDelete}
                  className="flex-1"
                  disabled={deleting}
                >
                  Cancel
                </Button>
                <button
                  onClick={handleConfirmDelete}
                  disabled={deleting}
                  className="flex-1 bg-red-600 hover:bg-red-700 text-white px-5 py-2.5 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {deleting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Deleting...</span>
                    </>
                  ) : (
                    <>
                      <Trash2 className="w-4 h-4" />
                      <span>Delete</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Access Denied Modal (Add Firewall Rules) */}
      {showAccessDenied_AddRules && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <div className="text-center py-6">
              <div className="bg-red-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <Lock className="w-8 h-8 text-red-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Access Denied</h3>
              <p className="text-slate-300 mb-1">
                You don't have permission to add firewall rules.
              </p>
              <p className="text-slate-400 text-sm mb-6">
                Only <span className="text-orange-400 font-medium">Admin</span>, <span className="text-orange-400 font-medium">Dev</span>, and <span className="text-orange-400 font-medium">CyberSec</span> roles can perform this action.
              </p>
              {userRole && (
                <p className="text-slate-500 text-xs mb-4">
                  Your current role: <span className="text-slate-400 font-medium">{userRole.toUpperCase()}</span>
                </p>
              )}
              <Button
                onClick={() => setShowAccessDenied_AddRules(false)}
                variant="secondary"
                className="w-full"
              >
                Close
              </Button>
            </div>
          </Card>
        </div>
      )}

      {/* Access Denied Modal (Delete Firewall Rules) */}
      {showAccessDenied_DltRules && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <div className="text-center py-6">
              <div className="bg-red-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <Lock className="w-8 h-8 text-red-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Access Denied</h3>
              <p className="text-slate-300 mb-1">
                You don't have permission to delete firewall rules.
              </p>
              <p className="text-slate-400 text-sm mb-6">
                Only <span className="text-orange-400 font-medium">Admin</span> roles can perform this action.
              </p>
              {userRole && (
                <p className="text-slate-500 text-xs mb-4">
                  Your current role: <span className="text-slate-400 font-medium">{userRole.toUpperCase()}</span>
                </p>
              )}
              <Button
                onClick={() => setShowAccessDenied_DltRules(false)}
                variant="secondary"
                className="w-full"
              >
                Close
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
};

export default FirewallRules;