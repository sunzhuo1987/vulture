INSERT INTO "style_tpl" VALUES(1,'Default','LOGIN','<script type="text/javascript" src="/static/script/jquery-1.8.3.min.js"></script>
<script type="text/javascript" src="/static/jstree/jquery.jstree.js"></script>
<script type="text/javascript">
function crawl(ok_auth, obj){
        if (obj.metadata.id in ok_auth){
                obj.data.icon = "/static/jstree/vert.png";
        obj.data.title += " : "+ok_auth[obj.metadata.id]
        }
        else if (obj.metadata.op){
                obj.state = "open";
                if (obj.metadata.op=="OR") obj.data.icon = "/static/jstree/u.png";
                else obj.data.icon = "/static/jstree/n.png";
        }
        else obj.data.icon = "/static/jstree/rouge.png";
        if (obj.children) for (var x in obj.children) crawl(ok_auth, obj.children[x])
}
function show_auth(ok_auth, todo_auth){
        crawl(ok_auth, todo_auth)
        $.jstree._themes = "/static/jstree/themes/";
        $(function () {
                $("#mytree").jstree({
                        plugins : [ "themes","json_data","ui",],
                        themes :  {theme:"vulture"},
                        json_data : {"data" :[ todo_auth, ]},
                });
        });
}
function flatten_auth(auth){
        if (auth.metadata.op){
                if (auth.children.length==1) auth = auth.children[0];
                else for (var i in auth.children)auth.children[i] = flatten_auth(auth.children[i])
        }
        return auth;
}
</script>','<div style="position: absolute; top:25%; left:25%;">
<div id="custom">
<h4>__ERRORS__</h4>
__FORM__
<div id="mytree" class="ctree"></div>
<script type="text/javascript" class="source">
__LOGGED_AUTH__
show_auth(ok_auth, flatten_auth(todo_auth))
</script>
</div></div>');
INSERT INTO "style_tpl" VALUES(2,'portal','PORTAL','','<div>
Bienvenue <strong>__LOGIN_NAME__ </strong> (
<a href="/logout">Logout</a> )
</div>
<div>
__APPS__
</div>');
INSERT INTO "style_tpl" VALUES(3,'Login-InWebo','LOGIN','<style>
a{
   text-decoration: none;
   font-weight: bold;
   color: green;
}
</style>
<script type="text/javascript" src="https://ult-inwebo.com/config/iwconfig.js"></script>
<script type="text/javascript" src="https://ult-inwebo.com/webapp/js/helium.min.js"></script>
<script src="/static/script/jquery-1.8.3.min.js"></script>
<script type="text/javascript">
$(document).ready(function() {
        if ($("#inweboAuth").length) {
                start_helium("inweboAuth",
                        function(iw,data){ if (data.result == "ok") { iw.insertFields(data); }
                                if (data.result == "nok" && data.error == "no_profile")
                                { start_helium("inweboActivate"); }})
        }})
</script>','<center>
<div style = "position: absolute; top:25%; left:25%;">
<div id="custom" style="margin: 0; padding: 60 30;">
<h3>Vulture by InWebo</h3>
<h2><font color="red">__ERRORS__</font></h2>
__FORM__
<a href="javascript:start_helium(\"inweboActivate\")">Enrôler mon navigateur dans Helium</a>
<br>
<a href="javascript:start_helium(\"inweboAuth\")">Se connecter avec Helium</a>
</div>
</div>
<div id="inweboAuth" action="authenticate" lang="fr"
alias="1234" style="display:none"></div> <div id="inweboActivate" action="activate" lang="fr"
alias="1234" style="display:none"></div>
</center>');

