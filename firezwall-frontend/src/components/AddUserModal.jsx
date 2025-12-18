import { useState, useMemo } from 'react';
import { X, UserPlus, AlertCircle, Check, XIcon } from 'lucide-react';
import Button from './ui/Button';
import Input from './ui/Input';
import Card from './ui/Card';
import Alert from './ui/Alert';

const AddUserModal = ({ isOpen, onClose, onSubmit, loading }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    role: 'user'
  });

  const [errors, setErrors] = useState({});
  const [apiError, setApiError] = useState('');

  if (!isOpen) return null;

  // Password strength requirements checker
  const passwordRequirements = useMemo(() => {
    const pwd = formData.password;
    return {
      length: pwd.length >= 8,
      uppercase: /[A-Z]/.test(pwd),
      lowercase: /[a-z]/.test(pwd),
      number: /[0-9]/.test(pwd),
      symbol: /[!@#$%^&*]/.test(pwd)
    };
  }, [formData.password]);

  // Check if password meets all requirements
  const isPasswordStrong = useMemo(() => {
    return Object.values(passwordRequirements).every(req => req === true);
  }, [passwordRequirements]);

  // Check if passwords match
  const passwordsMatch = useMemo(() => {
    if (!formData.confirmPassword) return null; // Not checked yet
    return formData.password === formData.confirmPassword;
  }, [formData.password, formData.confirmPassword]);

  const validateForm = () => {
    const newErrors = {};

    // Username validation
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
      newErrors.username = 'Username can only contain letters, numbers, and underscores';
    }

    // Password validation - check all requirements
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (!isPasswordStrong) {
      newErrors.password = 'Password does not meet all requirements';
    }

    // Confirm password validation
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError('');

    if (!validateForm()) {
      return;
    }

    const userData = {
      username: formData.username,
      password: formData.password,
      role: formData.role
    };

    try {
      await onSubmit(userData);
      handleClose();
    } catch (error) {
      console.error('Error adding user:', error);
      setApiError(error.message || 'Failed to create user');
    }
  };

  const handleClose = () => {
    setFormData({
      username: '',
      password: '',
      confirmPassword: '',
      role: 'user'
    });
    setErrors({});
    setApiError('');
    onClose();
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  // Requirement item component
  const RequirementItem = ({ met, children }) => (
    <div className="flex items-center gap-2">
      {met ? (
        <div className="flex-shrink-0 w-5 h-5 rounded-full bg-green-500/20 flex items-center justify-center">
          <Check className="w-3 h-3 text-green-400" />
        </div>
      ) : (
        <div className="flex-shrink-0 w-5 h-5 rounded-full bg-slate-700 flex items-center justify-center">
          <XIcon className="w-3 h-3 text-slate-500" />
        </div>
      )}
      <span className={`text-sm ${met ? 'text-green-400' : 'text-slate-400'}`}>
        {children}
      </span>
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background-color: rgba(148, 163, 184, 0.3);
          border-radius: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background-color: rgba(148, 163, 184, 0.5);
        }
      `}</style>
      <Card 
        className="w-full max-w-2xl max-h-[80vh] overflow-y-auto custom-scrollbar"
        onClick={(e) => e.stopPropagation()}
        style={{
          scrollbarWidth: 'thin',
          scrollbarColor: 'rgba(148, 163, 184, 0.3) transparent'
        }}
      >
        <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-orange-500 to-red-600 p-2 rounded-lg">
              <UserPlus className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">Create New User</h3>
              <p className="text-sm text-slate-400">Add a new user account</p>
            </div>
          </div>
          <button
            onClick={handleClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {apiError && (
          <Alert
            type="error"
            message={apiError}
            onClose={() => setApiError('')}
          />
        )}

        <form onSubmit={handleSubmit} className="space-y-5 mt-6">
          {/* Row 1: Username */}
          <Input
            label="Username"
            type="text"
            placeholder="Enter username"
            value={formData.username}
            onChange={(e) => handleInputChange('username', e.target.value)}
            error={errors.username}
          />

          {/* Row 2: Role */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Role <span className="text-red-400">*</span>
            </label>
            <select
              value={formData.role}
              onChange={(e) => handleInputChange('role', e.target.value)}
              className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
            >
              <option value="user">User</option>
              <option value="dev">Developer</option>
              <option value="cybersec">CyberSec</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          {/* Row 3: Password */}
          <Input
            label="Password"
            type="password"
            placeholder="Enter a strong password"
            value={formData.password}
            onChange={(e) => handleInputChange('password', e.target.value)}
            error={errors.password}
          />

          {/* Row 4: Confirm Password */}
          <div>
            <Input
              label="Confirm Password"
              type="password"
              placeholder="Re-enter password"
              value={formData.confirmPassword}
              onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
              error={errors.confirmPassword}
            />
            
            {/* Live Password Match Indicator */}
            {formData.confirmPassword && (
              <div className="mt-2 flex items-center gap-2">
                {passwordsMatch ? (
                  <>
                    <div className="flex-shrink-0 w-5 h-5 rounded-full bg-green-500/20 flex items-center justify-center">
                      <Check className="w-3 h-3 text-green-400" />
                    </div>
                    <span className="text-sm text-green-400">Passwords match</span>
                  </>
                ) : (
                  <>
                    <div className="flex-shrink-0 w-5 h-5 rounded-full bg-red-500/20 flex items-center justify-center">
                      <XIcon className="w-3 h-3 text-red-400" />
                    </div>
                    <span className="text-sm text-red-400">Passwords do not match</span>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Password Requirements */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <h4 className="text-sm font-semibold text-slate-300 mb-3">
              Password Requirements:
            </h4>
            <div className="space-y-2">
              <RequirementItem met={passwordRequirements.length}>
                At least 8 characters
              </RequirementItem>
              <RequirementItem met={passwordRequirements.uppercase}>
                Include uppercase letter (A-Z)
              </RequirementItem>
              <RequirementItem met={passwordRequirements.lowercase}>
                Include lowercase letter (a-z)
              </RequirementItem>
              <RequirementItem met={passwordRequirements.number}>
                Include number (0-9)
              </RequirementItem>
              <RequirementItem met={passwordRequirements.symbol}>
                Include symbol (!@#$%^&*)
              </RequirementItem>
            </div>
            
            {/* Overall Strength Indicator */}
            {formData.password && (
              <div className="mt-4 pt-3 border-t border-slate-700">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Password Strength:</span>
                  <span className={`text-sm font-semibold ${
                    isPasswordStrong 
                      ? 'text-green-400' 
                      : 'text-orange-400'
                  }`}>
                    {isPasswordStrong ? 'Strong ✓' : 'Weak'}
                  </span>
                </div>
                {/* Strength Bar */}
                <div className="mt-2 h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-300 ${
                      isPasswordStrong 
                        ? 'bg-green-500 w-full' 
                        : 'bg-orange-500'
                    }`}
                    style={{ 
                      width: `${(Object.values(passwordRequirements).filter(Boolean).length / 5) * 100}%` 
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Submit Buttons */}
          <div className="flex gap-3 pt-4 border-t border-slate-700">
            <Button
              type="button"
              variant="secondary"
              onClick={handleClose}
              className="flex-1"
              disabled={loading}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              className="flex-1"
              disabled={loading || !isPasswordStrong || !passwordsMatch}
            >
              {loading ? 'Creating User...' : 'Create User'}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
};

export default AddUserModal;