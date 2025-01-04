// Placeholder script for form submission
document.querySelector('form').addEventListener('submit', function (e) {
    e.preventDefault();
    const contactInput = document.getElementById('contact').value;
    if (isValidContact(contactInput)) {
        alert('Next Step: Verification!');
    } else {
        alert('Please enter a valid Phone Number or Email.');
    }
});

function isValidContact(contact) {
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const phonePattern = /^\d{10}$/;
    return emailPattern.test(contact) || phonePattern.test(contact);
}