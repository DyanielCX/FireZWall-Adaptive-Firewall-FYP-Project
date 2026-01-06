import { AlertCircle, CheckCircle, X } from 'lucide-react';

const Alert = ({ 
  type = 'error', 
  message, 
  onClose 
}) => {
  const types = {
    error: { 
      bg: 'bg-red-900/50', 
      border: 'border-red-500', 
      icon: AlertCircle, 
      color: 'text-red-400' 
    },
    success: { 
      bg: 'bg-green-900/50', 
      border: 'border-green-500', 
      icon: CheckCircle, 
      color: 'text-green-400' 
    }
  };

  const { bg, border, icon: Icon, color } = types[type];

  return (
    <div className={`${bg} ${border} border rounded-lg p-4 flex items-center gap-3`}>
      <Icon className={`w-5 h-5 ${color} flex-shrink-0`} />
      <p className={`${color} flex-1`}>{message}</p>
      {onClose && (
        <button 
          onClick={onClose} 
          className={`${color} hover:opacity-80 flex-shrink-0`}
        >
          <X className="w-4 h-4" />
        </button>
      )}
    </div>
  );
};

export default Alert;