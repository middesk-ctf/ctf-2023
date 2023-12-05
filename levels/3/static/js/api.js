// This object is useful for providing API methods throughout the app.
const api = {
    // Utility function to handle fetch requests
    fetchWithAuth: async function(url, options = {}) {
        const token = window.localStorage.getItem('token');
        if (token) {
            options.headers = options.headers || {};
            options.headers.Authorization = `Bearer ${token}`;
        }

        const response = await fetch(url, options);
        if (!response.ok) {
            const error = await response.json();
            if (response.status === 401) {
                // Assume the token expired. Force a logout.
                console.log(error.message);
                return api.logout();
            }
            throw new Error(error.message || 'An error occurred');
        }
        return response.json();
    },

    // Sign up
    signup: async function(username, password) {
        const response = await fetch('/v1/signup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        if (response.ok) {
            window.localStorage.setItem('token', data.token);
        } else {
            throw new Error(data.message);
        }
        return data;
    },

    // Log in
    login: async function(username, password) {
        const response = await fetch('/v1/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        if (response.ok) {
            window.localStorage.setItem('token', data.token);
        } else {
            throw new Error(data.message);
        }
        return data;
    },

    // Log out
    // NOTE: not async
    logout: function() {
        // Remove token from local storage
        // and immediately redirect to login page.
        window.localStorage.removeItem('token');
        window.location.href = "/login";
    },

    // Get current user
    getCurrentUser: async function() {
        return await api.fetchWithAuth('/v1/user');
    },

    // Update current user's display name
    updateDisplayName: async function(displayName) {
        return await api.fetchWithAuth('/v1/user', {
            method: 'PATCH',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({display_name: displayName})
        });
    },

    // List users
    listUsers: async function() {
        return await api.fetchWithAuth('/v1/users');
    },

    // List files
    listFiles: async function() {
        return await api.fetchWithAuth('/v1/files');
    },

    // Get file contents
    getFile: async function(file_id) {
        return await api.fetchWithAuth(`/v1/files/${file_id}`);
    }
};
