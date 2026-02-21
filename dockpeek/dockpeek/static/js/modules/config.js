const getApiPrefix = () => {
  const meta = document.querySelector('meta[name="api-prefix"]');
  return meta ? meta.content : '';
};

export const apiUrl = (path) => {
  const prefix = getApiPrefix();
  if (!prefix) {
    return path.startsWith('/') ? path : '/' + path;
  }
  
  const cleanPrefix = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  
  const cleanPath = path.startsWith('/') ? path : '/' + path;
  
  return cleanPrefix + cleanPath;
};

window.apiUrl = apiUrl;
export const config = {
  apiUrl,
};