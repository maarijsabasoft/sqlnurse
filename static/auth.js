let otpSent = false;

function openTab(tabName) {
    document.querySelectorAll('.tabcontent').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tablinks').forEach(tab => tab.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    document.querySelector(`button[onclick="openTab('${tabName}')"]`).classList.add('active');
    document.getElementById('login-error').style.display = 'none';
    document.getElementById('signup-error').style.display = 'none';
    otpSent = false;
    updateSignupForm();
}

function updateSignupForm() {
    const signupForm = document.getElementById('signup');
    const errorDiv = document.getElementById('signup-error');
    
    if (otpSent) {
        // Show OTP input field
        if (!document.getElementById('otp-input')) {
            const otpContainer = document.createElement('div');
            otpContainer.className = 'otp-container';
            otpContainer.innerHTML = `
                <input type="text" id="otp-input" placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{6}">
            `;
            signupForm.insertBefore(otpContainer, signupForm.querySelector('button.submit'));
        }
        errorDiv.style.color = '#6c757d';
        errorDiv.textContent = 'Please enter the verification code sent to your email.';
        errorDiv.style.display = 'block';
    } else {
        // Remove OTP input if exists
        const otpInput = document.getElementById('otp-input');
        if (otpInput) {
            otpInput.parentElement.remove();
        }
        errorDiv.style.display = 'none';
    }
}

async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const error = document.getElementById('login-error');
    if (!email || !password) {
        error.textContent = 'Email and password are required';
        error.style.display = 'block';
        return;
    }
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
            credentials: 'include'
        });
        const data = await response.json();
        if (data.error) {
            error.textContent = data.error;
            error.style.display = 'block';
        } else {
            window.location.href = data.redirect;
        }
    } catch (err) {
        error.textContent = 'An error occurred. Please try again.';
        error.style.display = 'block';
    }
}

async function signup() {
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const error = document.getElementById('signup-error');
    const otpInput = document.getElementById('otp-input');
    const otpCode = otpInput ? otpInput.value : null;

    if (!email || !password) {
        error.style.color = '#dc3545';
        error.textContent = 'Email and password are required';
        error.style.display = 'block';
        return;
    }

    try {
        const payload = { email, password };
        if (otpCode) {
            payload.otp_code = otpCode;
        }

        const response = await fetch('/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            credentials: 'include'
        });

        const data = await response.json();

        if (data.error) {
            error.style.color = '#dc3545';
            error.textContent = data.error;
            error.style.display = 'block';
        } else if (data.status === 'otp_sent') {
            otpSent = true;
            updateSignupForm();
            error.style.color = '#4bb543';
            error.textContent = data.message;
            error.style.display = 'block';
        } else {
            // Success
            error.style.color = '#4bb543';
            error.textContent = data.message || 'Signup successful!';
            error.style.display = 'block';

            setTimeout(() => {
                window.location.href = data.redirect || '/app';
            }, 1500);
        }
    } catch (err) {
        error.style.color = '#dc3545';
        error.textContent = 'An error occurred. Please try again.';
        error.style.display = 'block';
    }
}

