(function($){
    getHelp = function(){
        var xmlGet;
        var language = normaliseLang(navigator.language /* Mozilla */ || navigator.userLanguage /* IE */);
        var url = '/xml/help-' + language + '.xml';
        $.ajax({
            type: "GET",
            url: url,
            async: false,
            cache: false,
            dataType: "xml",
            success: function(xml) {
                xmlGet = xml;
            }
        });
        $(".main_content table tr").each(function() {
            var tr = $(this).closest("tr");
            var last_td = $(this).find("td:last");
            var input = tr.find(":input");
            var name = input.attr('name');
            var category = $(this).closest("form").attr('id');
            var help;
            if(xmlGet && category && name){
                help = $(xmlGet).find(category).find(name).text();
                if(help){
                    last_td.append('<div class="help">' + help + '</div>');
                    $(this).find(".support").bind("mouseover", {help: help}, function (e) {
                        last_td.find(".help").css("display", "block").css("top", (e.clientY + 10)).css("left", (e.clientX + 10));
                    }).bind("mouseout", {help: help}, function (e) {
                        last_td.find(".help").css("display", "none");
                    });
                } else {
                    $(this).find(".support").remove();
                }
            } else {
                $(this).find(".support").remove();
            }
        });
    };
})(jQuery);

/* Retrieve the default language set for the browser. */
/* Ensure language code is in the format aa-AA. */
/* Then, cut string to get only aa */
function normaliseLang(lang) {
    lang = lang.replace(/_/, '-').toLowerCase();
    if (lang.length > 3) {
        lang = lang.substring(0, 2)
    }
    return lang;
}