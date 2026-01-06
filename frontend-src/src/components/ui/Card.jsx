const Card = ({ 
  children, 
  className = '', 
  onClick, 
  hoverable = false 
}) => {
  const baseStyles = 'bg-slate-800 border border-slate-700 rounded-xl p-6';
  const hoverStyles = hoverable 
    ? 'hover:border-orange-500/50 hover:shadow-lg hover:shadow-orange-500/10 cursor-pointer transition-all duration-200' 
    : '';

  return (
    <div 
      onClick={onClick}
      className={`${baseStyles} ${hoverStyles} ${className}`}
    >
      {children}
    </div>
  );
};

export default Card;