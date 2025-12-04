import { useState, useEffect } from 'react';
import { Users, UserPlus, Trash2, RefreshCw, Lock, Filter, Shield } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import apiClient from '../api/client';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Alert from '../components/ui/Alert';
import AddUserModal from '../components/AddUserModal';

const UserManagement = () => {
  const { getToken } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [userRole, setUserRole] = useState(null);
  const [selectedRoleFilter, setSelectedRoleFilter] = useState('all');
  const [hasAccess, setHasAccess] = useState(null); // null = checking, true = has access, false = denied
  
  // Delete confirmation
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [userToDelete, setUserToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    checkAdminAccess();
  }, []);

  const checkAdminAccess = async () => {
    setLoading(true);
    try {
      const token = getToken();
      const response = await apiClient.getUserRole(token);
      
      if (response.success) {
        setUserRole(response.role);
        
        if (response.role !== 'admin') {
          // Not admin - show access denied
          setHasAccess(false);
          setLoading(false);
          return;
        }
        
        // Is admin - has access
        setHasAccess(true);
        // Fetch users
        fetchUsers();
      }
    } catch (err) {
      console.error('Error checking admin access:', err);
      setError('Failed to verify permissions');
      setHasAccess(false);
      setLoading(false);
    }
  };

  const fetchUsers = async (roleFilter = 'all') => {
    setLoading(true);
    setError('');
    
    try {
      const token = getToken();
      const response = await apiClient.getUsers(token, roleFilter);
      
      if (response.success) {
        setUsers(response.users || []);
      } else {
        setError('Failed to load users');
      }
    } catch (err) {
      console.error('Error fetching users:', err);
      setError(err.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  const handleRoleFilterChange = (role) => {
    setSelectedRoleFilter(role);
    fetchUsers(role);
  };

  const handleAddUser = () => {
    setShowAddModal(true);
  };

  const handleSubmitUser = async (userData) => {
    setSubmitting(true);
    setError('');
    setSuccess('');

    try {
      const token = getToken();
      const response = await apiClient.registerUser(token, userData);
      
      if (response.success) {
        setSuccess(response.messages || 'User created successfully!');
        await fetchUsers(selectedRoleFilter);
        setShowAddModal(false);
        setTimeout(() => setSuccess(''), 3000);
      }
    } catch (err) {
      console.error('Error creating user:', err);
      throw err;
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteClick = (user) => {
    setUserToDelete(user);
    setShowDeleteModal(true);
  };

  const handleConfirmDelete = async () => {
    if (!userToDelete) return;

    setDeleting(true);
    setError('');
    setSuccess('');

    try {
      const token = getToken();
      const response = await apiClient.deleteUser(token, userToDelete.username);
      
      if (response.success) {
        setSuccess(response.messages || 'User deleted successfully!');
        await fetchUsers(selectedRoleFilter);
        setShowDeleteModal(false);
        setUserToDelete(null);
        setTimeout(() => setSuccess(''), 3000);
      }
    } catch (err) {
      console.error('Error deleting user:', err);
      setError(err.message || 'Failed to delete user');
    } finally {
      setDeleting(false);
    }
  };

  const handleCancelDelete = () => {
    setShowDeleteModal(false);
    setUserToDelete(null);
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

  const getStatusBadge = (isActive) => {
    return isActive ? (
      <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-500/20 text-green-400">
        Active
      </span>
    ) : (
      <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-500/20 text-gray-400">
        Inactive
      </span>
    );
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

  // Show access denied page if not admin
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
              You don't have permission to access User Management.
            </p>
            <p className="text-slate-400 text-sm mb-6">
              Only <span className="text-red-400 font-medium">Admin</span> role can view and manage users.
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
                className="w-full"
              >
                Refresh Page
              </Button>
              <p className="text-slate-500 text-xs">
                If you believe this is an error, please contact your administrator.
              </p>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  // Show loading while fetching users (after access granted)
  if (loading && hasAccess === true) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-orange-500 animate-spin" />
        <span className="ml-3 text-slate-300">Loading users...</span>
      </div>
    );
  }

  // Main content (only shown to admins)
  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">User Management</h2>
          <p className="text-slate-400">
            Manage system users and permissions
            {users.length > 0 && (
              <span className="ml-2 text-xs px-2 py-1 rounded bg-slate-700 text-slate-300">
                {users.length} {users.length === 1 ? 'user' : 'users'}
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-3">
          <Button
            variant="secondary"
            onClick={() => fetchUsers(selectedRoleFilter)}
            className="flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
          <Button
            onClick={handleAddUser}
            className="flex items-center gap-2"
          >
            <UserPlus className="w-4 h-4" />
            Add User
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="mb-4">
          <Alert type="error" message={error} onClose={() => setError('')} />
        </div>
      )}

      {/* Success Alert */}
      {success && (
        <div className="mb-4">
          <Alert type="success" message={success} onClose={() => setSuccess('')} />
        </div>
      )}

      {/* Role Filter */}
      <div className="mb-4 flex items-center gap-3">
        <div className="flex items-center gap-2 text-slate-400">
          <Filter className="w-4 h-4" />
          <span className="text-sm font-medium">Filter by role:</span>
        </div>
        <div className="flex gap-2">
          {['all', 'admin', 'dev', 'cybersec', 'user'].map((role) => (
            <button
              key={role}
              onClick={() => handleRoleFilterChange(role)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                selectedRoleFilter === role
                  ? 'bg-orange-500 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              {role === 'all' ? 'All' : role.charAt(0).toUpperCase() + role.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Users Table */}
      <Card className="overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-700/50 border-b border-slate-600">
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  ID
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Username
                </th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Role
                </th>
                <th className="px-6 py-4 text-center text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-4 text-center text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {users.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center">
                    <Users className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                    <p className="text-slate-400 text-sm">
                      {selectedRoleFilter === 'all' ? 'No users found' : `No ${selectedRoleFilter} users found`}
                    </p>
                    <Button
                      variant="outline"
                      onClick={handleAddUser}
                      className="mt-4"
                    >
                      Add Your First User
                    </Button>
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="hover:bg-slate-700/30 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {user.id}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-gradient-to-br from-orange-500 to-red-600 rounded-full flex items-center justify-center">
                          <span className="text-white text-xs font-bold">
                            {user.username.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <span className="text-sm font-medium text-white">
                          {user.username}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium border ${getRoleBadgeColor(
                          user.role
                        )}`}
                      >
                        {user.role.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      {getStatusBadge(user.is_active)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-center">
                      <button
                        onClick={() => handleDeleteClick(user)}
                        className="inline-flex items-center justify-center w-8 h-8 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors"
                        title="Delete user"
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
      </Card>

      {/* Add User Modal */}
      {showAddModal && (
        <AddUserModal
          isOpen={showAddModal}
          onClose={() => setShowAddModal(false)}
          onSubmit={handleSubmitUser}
          loading={submitting}
        />
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && userToDelete && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <div className="text-center py-6">
              <div className="bg-red-500/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <Trash2 className="w-8 h-8 text-red-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Delete User</h3>
              <p className="text-slate-300 mb-4">
                Are you sure you want to delete this user?
              </p>
              
              <div className="bg-slate-700/50 rounded-lg p-4 mb-6 text-left">
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <span className="text-slate-400">Username:</span>
                  <span className="text-white font-medium">{userToDelete.username}</span>
                  
                  <span className="text-slate-400">Role:</span>
                  <span className="text-white font-medium">{userToDelete.role}</span>
                  
                  <span className="text-slate-400">User ID:</span>
                  <span className="text-white font-medium">{userToDelete.id}</span>
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
    </div>
  );
};

export default UserManagement;