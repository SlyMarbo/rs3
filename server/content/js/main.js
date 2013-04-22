var refresh = function refresh() {
	$(".invis").on('activate', function() {
		var id = $("li.active").attr('id').substring(5);
	  $('#' + id).addClass('read');
		var item = data[currentFeed][parseInt(id, 10)];
		if (!item.Read) {
			item.Read = true;
			--unread;
			if (unread == 0) $('#unread').html(unread).removeClass('unread').addClass('unread_zero');
			else $('#unread').html(unread);
		}
	});
}

var data = %s;
var currentFeed = %q;
var unread = %d;
$('.feed').click(function() {
	var feed = $(this)[0].innerText.replace(/\s\s*$/, '');
	currentFeed = feed;
	var out = [];
	var invis = [];
	var len = data[feed].length;
	for (var i = 0; i < len; ++i) {
		var item = data[feed][i]
		if (item['Read']) continue;
		out.push('<li><div class="item"><h3>')
		out.push(item['Title'])
		out.push('</h3><p>')
		out.push(item['Content'])
		out.push('</p><p class="text-right"><small>')
		out.push(item['Source'])
		out.push('</small></p></div></li>')
		
		invis.push('<li id="node_');
		invis.push(i.toString());
		invis.push('"><a href="#');
		invis.push(i.toString());
		invis.push('">');
		invis.push(i.toString());
		invis.push('</a></li>');
	}
	$('#items').html(out.join(''));
	$('#invisinsert').html(invis.join(''));
	$('.active').removeClass('active')
	$(this).addClass('active')
	$('.item').each(function () {
	  $(this).scrollspy('refresh')
	});
	$('#items').scrollTop(0);
	refresh();
});
refresh();