let savedTheme;
try {
  savedTheme = localStorage.getItem('theme');
} catch {}
document.documentElement.classList.toggle('dark', savedTheme !== 'light');
