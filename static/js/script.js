document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('analyze-form');
    const urlInput = document.getElementById('url-input');
    const loader = document.getElementById('loader');
    const resultDiv = document.getElementById('result');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const vulnerabilitiesList = document.getElementById('vulnerabilities-list');

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        const url = urlInput.value.trim();

        // Clear previous results and errors
        clearContent();

        // Validate URL format
        if (!isValidURL(url)) {
            showError('Please enter a valid URL. Example: https://www.example.com');
            return;
        }

        // Show loader
        loader.style.display = 'block';

        // Prepare data
        const data = { url: url };

        // Send POST request to /analyze
        fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        })
            .then(async (response) => {
                loader.style.display = 'none';
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || `Error: ${response.status}`);
                }
                return response.json();
            })
            .then((data) => {
                if (data.status === 'success') {
                    displayResult(data.data);
                    showSuccess('Analysis completed successfully.');
                } else {
                    throw new Error(data.message || 'Unknown error occurred.');
                }
            })
            .catch((error) => {
                showError(error.message);
            });
    });

    // Function to display analysis results
    function displayResult(data) {
        // Populate SEO Elements
        document.getElementById('title').innerText = data.title || 'N/A';
        document.getElementById('meta-description').innerText = data.meta_description || 'N/A';

        // Populate SSL Info
        if (data.ssl_info) {
            document.getElementById('ssl-version').innerText = data.ssl_info['SSL Version'] || 'N/A';
            document.getElementById('cipher').innerText = Array.isArray(data.ssl_info['Cipher']) ? data.ssl_info['Cipher'].join(', ') : 'N/A';
            document.getElementById('expires-on').innerText = data.ssl_info['Expires On'] || 'N/A';
            document.getElementById('days-until-expiry').innerText =
                data.ssl_info['Days Until Expiry'] !== undefined ? data.ssl_info['Days Until Expiry'] : 'N/A';
        } else {
            document.getElementById('ssl-version').innerText = 'N/A';
            document.getElementById('cipher').innerText = 'N/A';
            document.getElementById('expires-on').innerText = 'N/A';
            document.getElementById('days-until-expiry').innerText = 'N/A';
        }

        // Populate Vulnerabilities
        populateVulnerabilities(data.vulnerabilities);

        // Show result
        resultDiv.style.display = 'block';
    }

    // Function to populate vulnerabilities
    function populateVulnerabilities(vulnerabilities) {
        vulnerabilitiesList.innerHTML = '';  // Clear previous vulnerabilities

        // SQL Injection
        const sqlItem = document.createElement('li');
        sqlItem.innerHTML = `<strong>SQL Injection:</strong> ${vulnerabilities.sql_injection ? 'Vulnerable' : 'No issues detected'}`;
        sqlItem.classList.add(vulnerabilities.sql_injection ? 'vulnerable' : 'no-issue');
        vulnerabilitiesList.appendChild(sqlItem);

        // XSS
        const xssItem = document.createElement('li');
        xssItem.innerHTML = `<strong>XSS:</strong> ${vulnerabilities.xss ? 'Vulnerable' : 'No issues detected'}`;
        xssItem.classList.add(vulnerabilities.xss ? 'vulnerable' : 'no-issue');
        vulnerabilitiesList.appendChild(xssItem);

        // Open Ports (if available in the response)
        if (vulnerabilities.open_ports) {
            const openPortsItem = document.createElement('li');
            openPortsItem.innerHTML = `<strong>Open Ports:</strong> ${vulnerabilities.open_ports.length > 0 ? vulnerabilities.open_ports.join(', ') : 'No open ports detected'}`;
            openPortsItem.classList.add(vulnerabilities.open_ports.length > 0 ? 'vulnerable' : 'no-issue');
            vulnerabilitiesList.appendChild(openPortsItem);
        }

        // Directory Traversal
        const directoryTraversalItem = document.createElement('li');
        directoryTraversalItem.innerHTML = `<strong>Directory Traversal:</strong> ${vulnerabilities.directory_traversal ? 'Vulnerable' : 'No issues detected'}`;
        directoryTraversalItem.classList.add(vulnerabilities.directory_traversal ? 'vulnerable' : 'no-issue');
        vulnerabilitiesList.appendChild(directoryTraversalItem);
    }

    // Function to clear previous content
    function clearContent() {
        resultDiv.style.display = 'none';
        successMessage.style.display = 'none'; // Hide success message on new request
        errorMessage.style.display = 'none';
        document.getElementById('title').innerText = '';
        document.getElementById('meta-description').innerText = '';
        document.getElementById('ssl-version').innerText = '';
        document.getElementById('cipher').innerText = '';
        document.getElementById('expires-on').innerText = '';
        document.getElementById('days-until-expiry').innerText = '';
        vulnerabilitiesList.innerHTML = '';  // Clear vulnerabilities list
    }

    // Function to show error messages
    function showError(message) {
        errorMessage.innerHTML = `<strong>Error:</strong> ${message}`;
        errorMessage.style.display = 'block';
    }

    // Function to show success messages
    function showSuccess(message) {
        successMessage.innerHTML = `<strong>Success:</strong> ${message}`;
        successMessage.style.display = 'block';
    }

    // Function to validate URL format
    function isValidURL(url) {
        const urlPattern = /^(https?|ftp):\/\/([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+)(:\d+)?(\/[A-Za-z0-9-._~:/?#[\]@!$&'()*+,;=]*)?$/i;
        return urlPattern.test(url);
    }
});
