import { useState } from 'react';
import { X, Plus, AlertCircle } from 'lucide-react';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import Card from '../components/ui/Card';
import Alert from '../components/ui/Alert';

const AddFirewallRuleModal = ({ isOpen, onClose, onSubmit, loading }) => {
  // Form state
  const [formData, setFormData] = useState({
    action: 'allow',
    inputType: 'port', // 'port' or 'service'
    port: '',
    service: '',
    protocol: 'tcp',
    direction: 'in',
    ipv4: true,
    ipv6: false,
    source: ''
  });

  // Validation errors
  const [errors, setErrors] = useState({});
  const [apiError, setApiError] = useState('');

  if (!isOpen) return null;

  // Frontend validation
  const validateForm = () => {
    const newErrors = {};

    // Check if either port or service is provided
    if (formData.inputType === 'port') {
      if (!formData.port.trim()) {
        newErrors.port = 'Port is required';
      } else if (!/^\d+$/.test(formData.port)) {
        newErrors.port = 'Port must be a numeric value';
      } else {
        const portNum = parseInt(formData.port);
        if (portNum < 1 || portNum > 65535) {
          newErrors.port = 'Port must be between 1 and 65535';
        }
        if (!Number.isInteger(portNum)) {
          newErrors.port = 'Port must be a valid integer';
        }
      }
    } else {
      if (!formData.service.trim()) {
        newErrors.service = 'Service name is required';
      } else if (/^\d+$/.test(formData.service.trim())) {
        newErrors.service = 'Service must be a string, cannot be an integer';
      }
    }

    // Validate source if provided
    if (formData.source.trim()) {
      const source = formData.source.trim();
      
      // Basic IPv4/IPv6 and CIDR validation
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
      const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
      const anywhereRegex = /^(anywhere|any)$/i;
      
      if (!ipv4Regex.test(source) && !ipv6Regex.test(source) && !anywhereRegex.test(source)) {
        newErrors.source = 'Invalid IPv4/IPv6 address or CIDR subnet';
      }
    }

    // At least one IP version must be selected
    if (!formData.ipv4 && !formData.ipv6) {
      newErrors.ipVersion = 'At least one IP version (IPv4 or IPv6) must be enabled';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError('');

    // Frontend validation
    if (!validateForm()) {
      return;
    }

    // Prepare data for API
    const ruleData = {
      action: formData.action,
      protocol: formData.protocol,
      direction: formData.direction,
      ipv4: formData.ipv4,
      ipv6: formData.ipv6,
    };

    // Add port or service
    if (formData.inputType === 'port') {
      ruleData.port = formData.port;
    } else {
      ruleData.service = formData.service;
    }

    // Add source if provided
    if (formData.source.trim()) {
      ruleData.source = formData.source.trim();
    }

    try {
      await onSubmit(ruleData);
      handleClose();
    } catch (error) {
      console.error('Error adding rule:', error);
      setApiError(error.message || 'Failed to add firewall rule');
    }
  };

  const handleClose = () => {
    setFormData({
      action: 'allow',
      inputType: 'port',
      port: '',
      service: '',
      protocol: 'tcp',
      direction: 'in',
      ipv4: true,
      ipv6: false,
      source: ''
    });
    setErrors({});
    setApiError('');
    onClose();
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    // Clear error for this field
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-orange-500 to-red-600 p-2 rounded-lg">
              <Plus className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">Add Firewall Rule</h3>
              <p className="text-sm text-slate-400">Create a new firewall rule</p>
            </div>
          </div>
          <button
            onClick={handleClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* API Error Alert */}
        {apiError && (
          <Alert
            type="error"
            message={apiError}
            onClose={() => setApiError('')}
          />
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Action */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Action <span className="text-red-400">*</span>
            </label>
            <div className="grid grid-cols-3 gap-3">
              {['allow', 'deny', 'reject'].map((action) => (
                <button
                  key={action}
                  type="button"
                  onClick={() => handleInputChange('action', action)}
                  className={`px-4 py-2 rounded-lg capitalize font-medium transition-all ${
                    formData.action === action
                      ? 'bg-orange-500 text-white'
                      : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                  }`}
                >
                  {action}
                </button>
              ))}
            </div>
          </div>

          {/* Port/Service Selector */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Port or Service <span className="text-red-400">*</span>
            </label>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <button
                type="button"
                onClick={() => {
                  handleInputChange('inputType', 'port');
                  setErrors(prev => ({ ...prev, service: '' }));
                }}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  formData.inputType === 'port'
                    ? 'bg-orange-500 text-white'
                    : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                By Port Number
              </button>
              <button
                type="button"
                onClick={() => {
                  handleInputChange('inputType', 'service');
                  setErrors(prev => ({ ...prev, port: '' }));
                }}
                className={`px-4 py-2 rounded-lg font-medium transition-all ${
                  formData.inputType === 'service'
                    ? 'bg-orange-500 text-white'
                    : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                By Service Name
              </button>
            </div>
            
            {formData.inputType === 'port' ? (
              <Input
                type="text"
                placeholder="e.g., 80, 443, 8080"
                value={formData.port}
                onChange={(e) => handleInputChange('port', e.target.value)}
                error={errors.port}
              />
            ) : (
              <Input
                type="text"
                placeholder="e.g., ssh, http, https"
                value={formData.service}
                onChange={(e) => handleInputChange('service', e.target.value)}
                error={errors.service}
              />
            )}
          </div>

          {/* Protocol & Direction */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Protocol <span className="text-red-400">*</span>
              </label>
              <select
                value={formData.protocol}
                onChange={(e) => handleInputChange('protocol', e.target.value)}
                className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="any">Any</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Direction <span className="text-red-400">*</span>
              </label>
              <select
                value={formData.direction}
                onChange={(e) => handleInputChange('direction', e.target.value)}
                className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
              >
                <option value="in">Inbound (IN)</option>
                <option value="out">Outbound (OUT)</option>
              </select>
            </div>
          </div>

          {/* IP Versions */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-3">
              IP Versions <span className="text-red-400">*</span>
            </label>
            <div className="grid grid-cols-2 gap-4">
              <label className="flex items-center gap-3 p-3 bg-slate-700/50 rounded-lg cursor-pointer hover:bg-slate-700 transition-colors">
                <input
                  type="checkbox"
                  checked={formData.ipv4}
                  onChange={(e) => handleInputChange('ipv4', e.target.checked)}
                  className="w-5 h-5 rounded border-slate-600 text-orange-500 focus:ring-orange-500 focus:ring-offset-slate-800"
                />
                <span className="text-slate-300 font-medium">Enable IPv4</span>
              </label>
              <label className="flex items-center gap-3 p-3 bg-slate-700/50 rounded-lg cursor-pointer hover:bg-slate-700 transition-colors">
                <input
                  type="checkbox"
                  checked={formData.ipv6}
                  onChange={(e) => handleInputChange('ipv6', e.target.checked)}
                  className="w-5 h-5 rounded border-slate-600 text-orange-500 focus:ring-orange-500 focus:ring-offset-slate-800"
                />
                <span className="text-slate-300 font-medium">Enable IPv6</span>
              </label>
            </div>
            {errors.ipVersion && (
              <p className="text-red-400 text-sm mt-2">{errors.ipVersion}</p>
            )}
          </div>

          {/* Source */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Source (Optional)
            </label>
            <Input
              type="text"
              placeholder="e.g., 192.168.1.0/24, 2001:db8::/32"
              value={formData.source}
              onChange={(e) => handleInputChange('source', e.target.value)}
              error={errors.source}
            />
            <p className="text-slate-500 text-xs mt-1">
              Leave empty for any source, or specify IP address/CIDR subnet
            </p>
          </div>

          {/* Action Buttons */}
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
              disabled={loading}
            >
              {loading ? 'Adding Rule...' : 'Add Rule'}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
};

export default AddFirewallRuleModal;