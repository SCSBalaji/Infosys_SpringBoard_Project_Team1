document.querySelector('form').addEventListener('submit', function (e) {
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    const passwordFormat = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (newPassword && confirmPassword) {
        if (!passwordFormat.test(newPassword)) {
            alert('Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.');
            e.preventDefault(); // Prevent form submission if password does not meet criteria
        } else if (newPassword !== confirmPassword) {
            alert('Passwords do not match. Please try again.');
            e.preventDefault(); // Prevent form submission if passwords do not match
        } else {
            alert('Password reset successful!');
            // Allow the form to be submitted to the server
        }
    } else {
        alert('Please fill in both fields.');
        e.preventDefault(); // Prevent form submission if fields are empty
    }
});

