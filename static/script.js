function showResult() {
  var query = document.getElementById('query').value;
  
  // VULNERABLE: Directly inserting user input into innerHTML (XSS vulnerability)
  document.getElementById('result').innerHTML = '<p>Search results for: <strong>' + query + '</strong></p>';
  
  // Check if XSS payload was detected (user has exploited the vulnerability)
  if (query.includes('<') && query.includes('>')) {
    // Show the proceed button
    document.getElementById('next-stage').style.display = 'block';
  }
}

// Allow Enter key to trigger search
document.getElementById('query').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') {
    showResult();
  }
});