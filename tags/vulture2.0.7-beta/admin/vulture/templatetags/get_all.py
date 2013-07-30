from django.template import Library, Node
from django.db.models import get_model

register = Library()

class AllContentNode(Node):
    def __init__(self, model, varname):
        self.varname = varname
        self.model = get_model(*model.split('.'))

    def render(self, context):
        context[self.varname] = self.model._default_manager.all()
        return ''

def get_all(parser, token):
    """
        {% get_all app.Class as  = <var_value> %}
    """
    bits = token.contents.split()
    if len(bits) != 4:
        raise TemplateSyntaxError, "get_latest tag takes exactly four arguments"
    if bits[2] != 'as':
        raise TemplateSyntaxError, "third argument to get_latest tag must be 'as'"
    return AllContentNode(bits[1], bits[3])

get_all = register.tag(get_all)