class snort_template():
    def __init__(self, protocol="tcp", src_port="", dest_port="any", msg="{}", nocase="",content="content", rule_type="type", tag="tag: session, 10,packet;"):
        self.protocol = protocol
        self.src_port = src_port
        self.dest_port = dest_port
        self.msg = msg
        self.nocase=nocase
        self.rule_type = rule_type
        self.tag = tag
        self.user = None
        self.group = None
        self.team = None

    def set_owner(self, user, group, team):
        self.user = user
        self.group = group
        self.team = team

    def set_rule(self, name, msg, content, treament, date, document, desc):
        if self.user is None:
            raise Exception("set_owner(user, group, team) must be calld first")
        return f'alert {self.protocol} any any -> {self.dest_port} ( msg: "{self.msg.format(msg)}";' \
               f' {self.content} {content}; sid:0; rev:1; gid: 1000000;' \
               f'metadata: type: {self.rule_type}, team {self.team}, user {self.user}, group {self.group},' \
               f' name {name}, treatment {treament}, keywords None, date {date}, document {document}, desc {desc}) {self.tag}'


class ipfull(snort_template):
    def __init__(self):
        super(ipfull, self).__init__(src_port="any", msg="IP_RULE:{2}:IP_RULE", content)