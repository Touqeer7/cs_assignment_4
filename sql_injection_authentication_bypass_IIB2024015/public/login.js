// Only handles the login error and mode selection. Authentication is server-side.
const params = new URLSearchParams(window.location.search);
if (params.get('mode') === 'secure') document.querySelector('input[value="secure"]').checked = true;
if (params.get('error') === 'credentials') document.getElementById('error').hidden = false;
