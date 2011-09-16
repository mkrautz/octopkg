$(document).ready(function() {
	// Highlight the correct part of the nav bar
	$('.nav li a').each(function(i, v) {
		var a = $(v);
		if (a.attr('href') == window.location.pathname) {
			a.parent().attr('class', 'active');
		}
	});
})
