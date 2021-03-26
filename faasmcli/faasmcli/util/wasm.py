import warnings
import subprocess
import re
import os
import codecs
import random
import string

from faasmcli.util.env import WASM_OPT_BIN
from subprocess import check_output

warnings.filterwarnings("ignore", category=DeprecationWarning)


def get_random_string(length=8) -> str:
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def traverse(
    o, tree_types=(list, tuple)
):  # traverses list and all nested lists
    if isinstance(o, tree_types):
        for value in o:
            for subvalue in traverse(value, tree_types):
                yield subvalue
    else:
        yield o


def parse_sexp(sexp) -> list:
    dbg = False
    term_regex = r"""(?mx)
        \s*(?:
            (?P<brackl>\()|
            (?P<brackr>\))|
            (?P<num>\-?\d+\.\d+|\-?\d+)|
            (?P<sq>"[^"]*")|
            (?P<s>[^(^)\s]+)
           )"""

    stack = []
    out = []
    if dbg:
        print("%-6s %-14s %-44s %-s" % tuple("term value out stack".split()))
    for termtypes in re.finditer(term_regex, sexp):
        term, value = [(t, v) for t, v in termtypes.groupdict().items() if v][
            0
        ]
        if dbg:
            print("%-7s %-14s %-44r %-r" % (term, value, out, stack))
        if term == "brackl":
            stack.append(out)
            out = []
        elif term == "brackr":
            assert stack, "Trouble with nesting of brackets"
            tmpout, out = out, stack.pop(-1)
            out.append(tmpout)
        elif term == "num":
            v = float(value)
            if v.is_integer():
                v = int(v)
            out.append(v)
        elif term == "sq":
            out.append(value[1:-1])
        elif term == "s":
            out.append(value)
        else:
            raise NotImplementedError("Error: %r %s" % (term, value))
    assert not stack, "Trouble with nesting of brackets"
    return out[0]


def parse(s, strip_quotes=True):
    """
    Parse a sexp string, returning a nested list structure.

    If `strip_quotes' is True, strings in the sexp will lose their
    surrounding quotation marks:

    >>> parse('(:name "Eric")')
    [':name', 'Eric']

    >>> parse('(:name "Eric")', False)
    [':name', '"Eric"']

    By default, `strip_quotes' is True.
    """
    result, stack = [], []
    idx = 0

    _is_data = False
    while True:
        c = s[idx : idx + 1]

        if c == "(":
            stack.append(result)
            result = []
            idx += 1

        elif c == ")":
            cur, result = result, stack.pop()
            result.append(cur)
            idx += 1

        elif s[idx : idx + 2] == "#(":
            # '#(' is how elisp stores text properties in strings
            # (http://goo.gl/mzR4yQ)
            #
            # So what we do is skip past just the '#' sign and keep
            # parsing as normal.
            idx += 1

        elif re.search("[a-zA-Z:!@#]", c):
            m = re.search("([\w:!@#-]+)", s[idx:])
            value = m.group()
            if value == "nil":
                result.append([])
            else:
                if value == "data":
                    _is_data = True
                result.append(value)
            idx += len(m.group())

        elif c == '"':
            if _is_data:
                _is_data = False
                m = re.search('(^".*"\))', s[idx:])
                count = len(m.group()) - 1
                if strip_quotes:
                    result.append(m.group()[1:-2])
                else:
                    result.append(m.group())
            else:
                m = re.search('("[^"]+")', s[idx:])
                count = len(m.group())
                if strip_quotes:
                    result.append(m.group()[1:-1])
                else:
                    result.append(m.group())
            idx += count

        elif re.search("[-\d]", c):
            m = re.search("(-?\d+\.\d+)|(-?\d+)", s[idx:])
            value = float(m.group())
            if value.is_integer():
                value = int(value)
            result.append(value)
            idx += len(m.group())

        else:
            idx += 1

        if idx > len(s):
            break

    if stack:
        raise ValueError("Unbalanced parens: %r" % s)

    (sexp,) = result
    return sexp


class Block:  # instruction block
    def __init__(self, type_, meta, display, label):
        self._type = type_
        self._meta = meta
        self._display = display
        self._label = label

    @property
    def type_(self):
        return self._type

    @property
    def meta(self):
        return self._meta

    @property
    def display(self):
        return self._display

    @display.setter
    def display(self, value):
        self._display = value

    @property
    def label(self):
        return self._label

    def __eq__(self, other):
        if not isinstance(other, Block):
            return NotImplemented

        return self.label == other.label

    def __str__(self):
        return self._display


class CFGNode:  # node for cfgtree
    def __init__(self, block):
        self._block = block
        self._next = []
        self._previous = []
        self._entry = []
        self._outry = []

    def add_next(self, _next):
        self._next.append(_next)

    @property
    def next(self):
        return self._next

    def add_previous(self, prev):
        self._previous.append(prev)

    @property
    def previous(self):
        return self._previous

    def add_entry(self, entry):
        self._entry.append(entry)

    @property
    def entry(self):
        return self._entry

    def add_outry(self, outry):
        self._outry.append(outry)

    @property
    def outry(self):
        return self._outry

    @property
    def block(self):
        return self._block

    def __eq__(self, other):
        if not isinstance(other, CFGNode):
            return NotImplemented

        return self.block == other.block

    def __str__(self):
        a = "next: {}\n".format(list(self._next))
        a += "previous: {}\n".format(list(self._previous))
        a += "entry: {}\n".format(list(self._entry))
        a += "outry: {}\n".format(list(self._outry))

        return a


class Module:  # wasm module
    class ImportSection(list):  # import section
        def __init__(self):
            pass

    class DataSection(dict):  # data section
        def __init__(self):
            pass

    class FunctionSection(list):  # function section
        def __init__(self):
            pass

        def get(self, name):
            if type(name) == str:
                for function in self:
                    if function.name == name:
                        return function
            else:
                return None

    class ExportSection(dict):  # export section
        def __init__(self):
            pass

        def get(self, name):
            return self[name]

    class Function:  # function
        def __init__(self, name, params=None, results=None, body=None):
            self._name = name
            self._params = params
            self._results = results
            self._body = body

        @property
        def name(self):
            return self._name

        @name.setter
        def name(self, name):
            self._name = name

        @property
        def params(self):
            return self._params

        @params.setter
        def params(self, params):
            self._params = params

        @property
        def results(self):
            return self._results

        @results.setter
        def results(self, results):
            self._results = results

        @property
        def body(self):
            return self._body

        @body.setter
        def body(self, body):
            self._body = body

        def get_calls(self) -> list:
            bodyt = list(traverse(self._body))
            calls = []

            for index, instruction in enumerate(bodyt):
                if instruction == "call":
                    reference = bodyt[index + 1]
                    if reference not in calls:
                        if reference != self.name:
                            calls.append(reference)

            return calls

        def get_lists(self, block) -> list:
            result = []

            for a in block:
                if isinstance(a, list):
                    result.append(a)

            return result

    class CallNode:  # node for callstacktree
        def __init__(self, name):
            self._name = name
            self._children = []
            self._parent = None

        @property
        def name(self):
            return self._name

        @property
        def parent(self):
            return self._parent

        @parent.setter
        def parent(self, node):
            self._parent = node

        @property
        def children(self):
            return self._children

        def add_child(self, node):
            self._children.append(node)

        def __str__(self):
            return self.name

    def __init__(self, name, functions=None):
        self._name = name
        self._functions = Module.FunctionSection()
        self._data = Module.DataSection()
        self._import = Module.ImportSection()
        self._display_name = os.path.basename(os.path.dirname(name))

    @property
    def display_name(self):
        return self._display_name

    @property
    def name(self):
        return self._name

    @property
    def function(self):
        return self._functions

    @function.setter
    def function(self, functions):
        self._functions = functions

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, data):
        self._data = data

    @property
    def import_(self):
        return self._import

    @import_.setter
    def import_(self, imports):
        self._import = imports

    def create_callstack_tree(
        self, function
    ) -> CallNode:  # creates callstacktree for function
        """
        @param function
        @return callstack-tree

        """

        work = [function.get_calls()]
        current_node = self.CallNode("tree")
        current_node.parent = current_node

        while len(work) != 0:
            if len(work[-1]) == 0:
                current_node = current_node.parent
                del work[-1]
                continue
            current = work[-1][0]
            del work[-1][0]

            tmp = self.CallNode(current)
            tmp.parent = current_node
            current_node.add_child(tmp)

            import_functions = [imp[0] for imp in self._import]
            if current in import_functions:
                continue

            functions = self._functions.get(current)
            if functions is None:
                print(
                    "warning: no functions found while creating call stack tree"
                )  # TODO this should not happen
                continue
            calls = functions.get_calls()
            if len(calls) == 0:
                continue
            else:
                ids = []  # TODO expe
                for id, ca in enumerate(calls):
                    if str(ca) == str(tmp.parent):
                        ids.append(id)

                for id in list(reversed(ids)):
                    del calls[id]
                current_node = tmp
                work.append(calls)

        return current_node

    def create_callstack(
        self, function
    ) -> list:  # creates callstack from tree for function
        """
        @param function
        @return callstack

        """

        if not isinstance(function, self.Function):
            return None

        tree = self.create_callstack_tree(function)

        result_stack = []  # TODO set, maybe dont check stacks twice
        childs = list(reversed(tree.children))

        while len(childs) != 0:
            current = childs[-1]
            del childs[-1]
            result_stack.append(current.name)
            tmp = list(reversed(current.children))

            childs += tmp

        return result_stack

    def get_chained_functions(
        self,
    ) -> list:  # searches the whole module for $faasmChainNamed-Calls
        """
        @param module parsed module
        @result list with all function names

        """

        chained = set()  # final set
        import_name = ""  # name of imported __faasm_chain_name
        function_calling_faasm_chain_name = None
        for imp in self._import:
            if imp[1] == "__faasm_chain_name":
                import_name = imp[0]

        # find functions calling that import
        for function in self._functions:
            for call in function.get_calls():
                if call == import_name:
                    function_calling_faasm_chain_name = function

        if function_calling_faasm_chain_name is None:
            return (
                list()
            )  # return emtpy list because no functions call faasm_chain_name

        # find places at which that function is called
        for function in self._functions:
            body = function.body
            tbody = list(traverse(body))
            for index, op in enumerate(tbody):
                if (
                    op == "call"
                    and tbody[index + 1]
                    == function_calling_faasm_chain_name.name
                ):
                    # if such place is found, use the operand to
                    # retrieve the called function names from the data section
                    operand = tbody[index + 3]
                    functionname = self._data[operand]
                    chained.add(functionname.replace("\x00", ""))

        return list(chained)

    # TODO maybe merge function with create_cfg
    def create_cfg(self, function, filter_, id=-1) -> CFGNode:
        """
        @param function
        @return cfg-tree
        """
        if not isinstance(function, self.Function):
            return None  # TODO exception is better

        namespace = get_random_string()
        a = [[]]
        a[0].append("start")

        # precheck
        _found = False
        for func in function.body:  # filter shitty calls
            funct = list(traverse(func))
            if (
                "$faasmAwaitCall" in funct
                or "$faasmChain" in funct
                or "$faasmChainNamed" in funct
                or "$faasmWriteState" in funct
            ):
                _found = True

        _found2 = False
        for i, func in enumerate(function.body):  # filter shitty calls
            funct = list(traverse(func))
            # if "call" in funct or "return" in funct:
            if func[0] == "local.set" and _found:
                a[0].append(func)
                _found2 = True
            elif (
                "$faasmAwaitCall" in funct
                or "$faasmChain" in funct
                or "$faasmChainNamed" in funct
                or "$faasmWriteState" in funct
            ):
                a[0].append(func)
                _found2 = True
            elif "call" in funct:
                for i, name in enumerate(funct):
                    if name == "call":
                        tmp_func = self.function.get(funct[i + 1])
                        stack = self.create_callstack(tmp_func)
                        if stack is not None:
                            if (
                                "$faasmAwaitCall" in stack
                                or "$faasmChain" in stack
                                or "$faasmChainNamed" in stack
                                or "$faasmWriteState" in stack
                            ):
                                _found2 = True
                                a[0].append(func)
            elif "return" in funct:
                a[0].append(func)

        work_stack = []
        work_stack.append(a)

        idx = 0
        cfg_start_block = Block("start", None, "start", namespace + str(idx))
        idx += 1
        start_node = CFGNode(cfg_start_block)
        last_node_stack = [[start_node]]

        cfg_end_block = Block(
            "end",
            None,
            "end: " + self._display_name + ":" + str(id),
            namespace + str(idx),
        )  # TODO hard
        idx += 1

        if not _found2:
            s_block = CFGNode(
                Block(
                    "start",
                    None,
                    "start: " + self._display_name + ":" + str(id),
                    namespace + str(idx),
                )
            )
            idx += 1
            start_node.add_next(s_block)
            cfg_end_block = CFGNode(
                Block(
                    "end",
                    None,
                    "end: " + self._display_name + ":" + str(id),
                    namespace + str(idx),
                )
            )
            s_block.add_next(cfg_end_block)
            return start_node

        while len(work_stack) != 0:
            if len(work_stack[-1]) == 0:
                work_stack.pop()
                last_node_stack.pop()
                continue

            current = work_stack[-1].pop(0)
            if len(last_node_stack[-1]) != 0:
                last_node = last_node_stack[-1][-1]
            else:
                last_node = last_node_stack[-2][-1]

            nested_lists = function.get_lists(current)
            tra = list(traverse(current))

            if (
                "call" not in tra
                and "br" not in tra
                and "block" not in tra
                and "return" not in tra
                and "start" not in tra
                and "local.set" not in tra
            ):
                continue

            is_call = False
            if "start" == current[0]:
                block = Block(
                    "start",
                    None,
                    "start: " + self._display_name + ":" + str(id),
                    namespace + str(idx),
                )

            elif "return" == current[0]:
                block = Block(
                    "return", namespace, "return", namespace + str(idx)
                )
                block = cfg_end_block

            elif "if" == current[0]:
                block = Block("if", current[1], "if", namespace + str(idx))

            elif "loop" == current[0]:
                block = Block("loop", current, "loop", namespace + current[1])

            elif "block" == current[0]:
                if not isinstance(current[1], list):
                    block = Block(
                        "block", current, "block", namespace + current[1]
                    )
                else:
                    block = Block(
                        "block", current, "block", namespace + str(idx)
                    )
            elif "call" in tra:
                is_call = True

                if (
                    current[0] == "call"
                ):  # direct call, without setting local.set
                    display = current[1]
                    if len(current) > 2:
                        meta = current[2]
                    else:
                        meta = None
                elif (
                    current[2][0] == "call"
                ):  # call in connection with local.set
                    if len(current[2]) > 2:
                        meta = current[2][2]
                        display = current[2][1]
                    else:  # function call without values
                        meta = None
                        display = current[2][1]
                else:
                    raise NotImplementedError  # should not happen

                if "$faasmAwaitCallOutput" in tra:
                    if current[2][0] == "call":
                        reference = current[2][2][1]
                    else:
                        raise NotImplementedError

                    # traceback
                    tmp_current = current_node
                    while tmp_current != start_node:
                        tmp_current_block = tmp_current.block
                        if tmp_current_block.type_ == "set":
                            if tmp_current_block.meta[1] == reference:
                                reference = tmp_current_block.meta[2][1]
                        elif tmp_current_block.type_ == "chain-call":
                            if len(tmp_current_block.meta) > 0:
                                if tmp_current_block.meta[0] == "chain":
                                    if tmp_current_block.meta[1] == reference:
                                        if len(tmp_current_block.meta) == 3:
                                            block = Block(
                                                "await-call",
                                                meta,
                                                tmp_current_block.meta[2]
                                                + ":0",
                                                namespace + str(idx),
                                            )  # TODO namespace dynamic
                                        elif len(tmp_current_block.meta) == 4:
                                            block = Block(
                                                "await-call",
                                                meta,
                                                tmp_current_block.meta[2]
                                                + ":"
                                                + str(
                                                    tmp_current_block.meta[3]
                                                ),
                                                namespace + str(idx),
                                            )
                                        else:
                                            raise NotImplementedError
                                        break

                        tmp_current = tmp_current.previous[0]

                    if (
                        tmp_current == start_node
                    ):  # this case should not pass... dev error
                        raise NotImplementedError

                elif "$faasmChain" in tra:
                    meta_new = ["chain", current[1], self.data[meta[1]]]
                    block = Block(
                        "chain-call",
                        meta_new,
                        self.data[meta[1]] + ":0",
                        namespace + str(idx),
                    )
                elif "$faasmChainNamed" in tra:
                    meta_new = [
                        "chain",
                        current[1],
                        self._display_name,
                        current[2][2][1],
                    ]
                    block = Block(
                        "chain-call",
                        meta_new,
                        self._display_name + ":" + str(meta_new[3]),
                        namespace + str(idx),
                    )
                elif "$faasmWriteState" in tra:
                    block = Block(
                        "write",
                        meta,
                        "write:{}".format(self.data[meta[1]]),
                        namespace + str(idx),
                    )
                else:
                    tmp_func = self.function.get(display)

                    if tmp_func is None:
                        continue

                    tree_ = self.create_cfg(tmp_func, filter_, id)
                    next__ = tree_.next[0]
                    if next__.next[0].block.type_ == "end":
                        continue
                    stack_ = list(reversed(tree_.next))
                    last_node.add_next(tree_.next[0])
                    tree_.next[0].previous = [last_node]
                    while len(stack_) != 0:
                        node_ = stack_.pop()
                        next_nodes_ = node_.next
                        block_ = node_.block

                        if block_.type_ == "end":
                            current_node = node_
                            break

                        stack_ += next_nodes_

                    last_node_stack[-1].append(current_node)
                    continue

            elif "br" == current[0]:
                current[1] = namespace + current[1]
                block = Block("br", current, "br", namespace + str(idx))
            elif "local.set" == current[0]:
                block = Block(
                    "set", current, "filter me (set)", namespace + str(idx)
                )
                is_call = True
                # local sets have not to be analysed much deeper
                # because of wasm-opt no nesting for sets

            else:
                raise NotImplementedError

            idx += 1
            current_node = CFGNode(block)

            last_node.add_next(current_node)
            current_node.add_previous(last_node)

            last_node_stack[-1].append(current_node)

            if is_call:
                continue

            if len(nested_lists) != 0:
                last_node_stack.append([])
                work_stack.append(nested_lists)

        def remove_useless_blocks(tree) -> None:
            """
            removes sets and chain calls from tree
            @param tree cfg tree

            """

            stack = list(reversed(tree.next))

            while len(stack) != 0:
                node = stack.pop()

                next_nodes = node.next
                previous_nodes = node.previous

                block = node.block

                if block.type_ == "set" or block.type_ in filter_:
                    # if block.type_ == "set" or block.type_ == "chain-call":
                    for previous_node in previous_nodes:
                        previous_node.next.remove(node)
                        for next_node in next_nodes:
                            next_node.previous.remove(node)
                            next_node.add_previous(previous_node)
                            previous_node.add_next(next_node)

                stack += next_nodes

        def add_branches(tree) -> None:  # branch and remove br and continue
            """
            @param tree cfg tree

            """

            stack = list(reversed(tree.next))

            while len(stack) != 0:
                node = stack.pop()

                next_nodes = node.next
                previous_nodes = node.previous
                outry_nodes = node.outry
                entry_nodes = node.entry

                block = node.block

                if block.type_ == "block":  # add br
                    if len(next_nodes) < 3:
                        next_node_tmp = next_nodes[1]
                        node.next.remove(next_node_tmp)
                        next_node_tmp.previous.remove(node)

                        search_stack = [next_nodes[0]]
                        while len(search_stack) != 0:
                            tmp_next = search_stack[0].next

                            tmp = search_stack.pop(0)

                            if tmp.block.type_ == "br":
                                if tmp.block.meta[1] == block.label:
                                    # concat br and br block
                                    tmp.add_next(next_node_tmp)
                                    next_node_tmp.add_previous(tmp)

                                    # clean br
                                    for tmp_previous_node in tmp.previous:
                                        tmp_previous_node.next.remove(tmp)
                                        for tmp_next_node in tmp.next:
                                            tmp_next_node.previous.remove(tmp)
                                            tmp_next_node.add_previous(
                                                tmp_previous_node
                                            )
                                            tmp_previous_node.add_next(
                                                tmp_next_node
                                            )

                            search_stack = search_stack + tmp_next

                            # clean block
                        for previous_node in previous_nodes:
                            previous_node.next.remove(node)
                            for next_node in next_nodes:
                                next_node.previous.remove(node)
                                next_node.add_previous(previous_node)
                                previous_node.add_next(next_node)

                    else:
                        raise NotImplementedError  # should not happen

                stack += next_nodes

            stack = list(reversed(tree.next))

            while len(stack) != 0:
                node = stack.pop()

                next_nodes = node.next
                previous_nodes = node.previous
                outry_nodes = node.outry
                entry_nodes = node.entry

                block = node.block

                if block.type_ == "loop":
                    if len(next_nodes) == 1:
                        search_stack = [next_nodes[0]]
                        while len(search_stack) != 0:
                            tmp_next = search_stack[0].next

                            tmp = search_stack.pop(0)

                            if tmp.block.type_ == "br":
                                if tmp.block.meta[1] == block.label:
                                    # concat br and clean br block

                                    for tmp_previous_node in tmp.previous:
                                        tmp_previous_node.next.remove(tmp)
                                        tmp_previous_node.add_outry(node)
                                        node.add_entry(tmp_previous_node)

                            search_stack = search_stack + tmp_next

                        if len(outry_nodes) > 0:
                            raise NotImplementedError  # should not happen

                        for next_node in next_nodes:
                            next_node.previous.remove(node)

                            for previous_node in previous_nodes:
                                next_node.add_previous(previous_node)
                                previous_node.add_next(next_node)
                                previous_node.next.remove(node)

                            for entry_node in entry_nodes:
                                entry_node.outry.remove(node)
                                next_node.add_entry(entry_node)
                                entry_node.add_outry(next_node)

                    else:
                        raise NotImplementedError  # shoud not happen

                stack += next_nodes

        def minimize(tree) -> None:  # removes if blocks
            """
            @param tree cfg tree

            """

            stack = list(reversed(tree.next))

            while len(stack) != 0:
                node = stack.pop()

                next_nodes = node.next
                previous_nodes = node.previous
                entry_nodes = node.entry

                block = node.block

                if block.type_ == "if":
                    if len(entry_nodes) > 0:
                        # while loop with condition
                        if len(next_nodes) == 2:
                            # scan loop body

                            result = False
                            body_ = next_nodes[0]
                            next_ = next_nodes[1]
                            search_stack = [body_]
                            while len(search_stack) != 0:
                                tmp_next = search_stack[0].next

                                tmp = search_stack.pop(0)

                                tmp_outry_nodes = tmp.outry
                                if len(tmp_outry_nodes) > 0:
                                    result = node in tmp_outry_nodes
                                    break

                                search_stack = search_stack + tmp_next

                            if not result:
                                next_ = next_nodes[0]
                                body_ = next_nodes[1]

                            node.next.remove(next_)
                            next_.previous.remove(node)

                            if len(previous_nodes) > 1:
                                raise NotImplementedError  # shoud not happen
                            else:
                                previous_nodes[0].next.remove(node)
                                previous_nodes[0].add_next(next_)
                                next_.add_previous(previous_nodes[0])

                                previous_nodes[0].add_next(body_)
                                body_.previous.remove(node)
                                body_.add_next(next_)

                                body_.outry.remove(node)
                                body_.add_outry(body_)

                        else:
                            raise NotImplementedError  # shoud not happen

                stack += next_nodes

        remove_useless_blocks(start_node)
        # add_branches(start_node)
        minimize(start_node)

        return start_node

    def create_verify(self, function, id):
        return self.create_cfg(function, ["chain-call", "write"], id)

    def create_ccp(self, function, id):
        return self.create_cfg(function, ["await-call"], id)


def parse_wat(wasm_file, wat, data) -> Module:  # parses wat to module
    """
    @param wasm_file file
    @wat wasm_file in wat s-expressions
    @return module

    """

    m = Module(wasm_file)

    fsec = Module.FunctionSection()
    dsec = Module.DataSection()
    isec = Module.ImportSection()
    esec = Module.ExportSection()

    # content = parse(wat)
    content = parse_sexp(wat)
    content = content + data
    for statement in content:
        if isinstance(statement, list):
            if statement[0] == "func":
                f = Module.Function(statement[1])

                params = []
                results = []
                body = []

                statement = statement[3:]
                for line in statement:
                    if line[0] == "param":
                        params.append(line)
                    else:
                        break

                statement = statement[len(params) :]
                for line in statement:
                    if line[0] == "result":
                        results.append(line)
                    else:
                        break

                statement = statement[len(results) :]
                for line in statement:
                    body.append(line)

                f.params = params
                f.results = results
                f.body = body

                fsec.append(f)
            elif statement[0] == "data":
                entry = statement[1][2]
                # print(statement[1][2])
                data = codecs.escape_decode(
                    bytes(statement[2], "utf-8").decode("utf-8")
                )
                data = data[0]
                index = entry
                string = ""
                for i, char in enumerate(data):
                    entry += 1
                    if char == 0 or i == len(data) - 1:
                        if string is not None:
                            if i == len(data) - 1:
                                string += chr(char)

                            dsec[index] = string

                        index = entry
                        string = None
                    else:
                        if string is None:
                            string = ""
                        string += chr(char)

            elif statement[0] == "import":
                to_append = (
                    statement[3][1],
                    statement[2],
                )  # tupel: (import name, function name)
                isec.append(to_append)
            elif statement[0] == "export":
                if (
                    statement[2][0] == "func"
                ):  # only consider exported functions for now
                    # ['export', '_start', ['func', '$1']]
                    export_name = statement[1]
                    func_id = statement[2][1]
                    esec[export_name] = func_id

    m.function = fsec
    m.data = dsec
    m.import_ = isec
    m.export = esec

    return m


def generate_wat(wasm_file) -> str:  # generates wat with binaryen wasm-opt
    """
    @param wasm_file
    @return wat in sexp
    """

    cmd = [
        WASM_OPT_BIN,
        "--flatten",
        "--rereloop",
        "--dce",
        "--merge-blocks",
        "--print",
        "--quiet",
        wasm_file,
    ]
    try:
        out = check_output(cmd).decode()
        return out
    except subprocess.CalledProcessError as error:
        raise SystemExit(error)
    except FileNotFoundError as error:
        print("Couldn't find wasm-opt binary. Please install wasm-opt!")
        raise SystemExit(error)


def parse_module(wasm_file) -> Module:  # creates module from wasm_file
    """
    @param wasm_file input
    @return module

    """

    wat = generate_wat(wasm_file)
    index = 0
    data = []
    while True:
        if wat[index : index + 5].startswith("(data"):
            m = re.search('(\(data\s\(.*\)\s".*\))', wat[index:])
            if m is not None:
                wat = wat[0:index] + wat[index + len(m.group()) + 2 :]
                to_append = parse(m.group())
                data.append(to_append)
        else:
            index += 1

        if index - 1 == len(wat):
            break

    return parse_wat(wasm_file, wat, data)
