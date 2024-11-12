// script.js
$(document).ready(function() {
    $('#searchForm').submit(function(event) {
        event.preventDefault();
        var query = $('#searchInput').val();
        var currentUrl = window.location.href;
        var searchUrl = currentUrl + '?search=' + query;
        window.location.href = searchUrl;
    });
});
