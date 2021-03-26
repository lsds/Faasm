def parse_verify(verify):
    state_verifies = {}
    for k, v in verify.items():
        state_verifies[k] = {}
        for i, j in v.items():
            object = parse_verify2(j)
            tmp = {}
            tmp[i] = object
            state_verifies[k].update(tmp)
    return state_verifies


def parse_verify2(j):
    objects = list()
    for object in j["objects"]:
        objects.append(object["label"])
    edges = list()
    for i in range(0, len(objects)):
        edges.append([])
        for a in j["edges"]:
            if a["tail"] == i:
                edges[i].append(a["head"])
    object = {"nodes": objects, "edges": edges}
    return object


class Verifier:
    def __init__(self, func, hash_list, verify_graph, verify_chain_graph):
        self._func = func
        self._hash_list = hash_list
        self._verify = parse_verify(verify_graph)
        self._verify_chain = parse_verify(verify_chain_graph)

    def is_valid_execution(self, stack):
        return self._is_valid_execution(stack, self._func)

    def _is_valid_execution(self, stack, name, id=0):
        if name not in self._verify:
            return False
        verify_objects = self._verify[name][str(id)]["nodes"]
        verify_edges = self._verify[name][str(id)]["edges"]
        next_function = []
        current_index = 0
        while len(stack[current_index:]) > 0:
            tmp_stack = stack[current_index:]
            meta_char = tmp_stack[0]
            if meta_char == "<" and current_index == 0:
                for _index, _char in enumerate(tmp_stack):
                    if _char == ",":
                        break
                    elif _char == ">":
                        break
                current_index = _index
                func = tmp_stack[1:current_index]
                _split = func.split(":")
                func = "{}:{}".format(_split[0], _split[2])
                if self._hash_list[_split[0]] != _split[1]:
                    return False
                if func != verify_objects[0].split(" ")[1]:
                    return False
                next_function = verify_edges[0]
            elif meta_char == ",":
                current_index += 1
            elif meta_char == ">":
                _found = False
                for next_id in next_function:
                    if verify_objects[next_id] == "end: {}:{}".format(
                        name, id
                    ):
                        _found = True
                        break
                if not _found:
                    return False
                current_index += 1
            elif meta_char == "<":
                _count = 0
                for _index, _char in enumerate(tmp_stack):
                    if _char == "<":
                        _count += 1
                    if _char == ">":
                        if _count == 0:
                            break
                        else:
                            _count -= 1
                current_index += _index
                new_stack = tmp_stack[0:_index]
                split = new_stack.split(",")
                if len(split) == 1:
                    func = split[0][1:-1]
                else:
                    func = split[0][1:]
                _found = False
                _split = func.split(":")
                func = "{}:{}".format(_split[0], _split[2])
                for next_id in next_function:
                    if verify_objects[next_id] == func:
                        next_function = verify_edges[next_id]
                        _found = True
                        break
                if not _found:
                    return False
                func_ = _split[0]
                _id = _split[2]
                if not self._is_valid_execution(new_stack, func_, _id):
                    return False
            elif meta_char == "[":  # state
                _count = 0
                for _index, _char in enumerate(tmp_stack):
                    if _char == "[":
                        _count += 1
                    if _char == "]":
                        if _count == 0:
                            break
                        else:
                            _count -= 1
                current_index += _index
                state = tmp_stack[0:_index][1:-1]
                state_key, execution_stack = state.split(";")  # cleanup
                reversed_execution_stack = execution_stack[::-1]
                _count = 0
                for _index, _char in enumerate(reversed_execution_stack):
                    if _char == ">":
                        _count += 1
                    if _char == "<":
                        _count -= 1
                        if _count < 0:
                            break
                split = reversed_execution_stack[0:_index][::-1].split(":")
                last_writer_func = split[0]
                last_writer_id = split[2][0]  # TODO id > 10...
                for _index, _label in enumerate(
                    list(
                        reversed(
                            self._verify_chain[last_writer_func][
                                str(int(last_writer_id))
                            ]["nodes"]
                        )
                    )
                ):
                    if _label == "write:{}".format(state_key):
                        last = (
                            len(
                                self._verify_chain[last_writer_func][
                                    str(int(last_writer_id))
                                ]["nodes"]
                            )
                            - 1
                            - _index
                        )
                        break
                cur = 0
                internal = True
                while cur < len(reversed_execution_stack):
                    char = reversed_execution_stack[cur]
                    if char == ">":
                        _count = 0
                        for _index, _char in enumerate(
                            reversed_execution_stack[cur:]
                        ):
                            if _char == ">":
                                if _count == 0:
                                    _start = _index
                                _count += 1
                            if _char == "<":
                                _count -= 1
                                if _count == 0:
                                    _end = _index
                                    break
                        cur = _end + 1
                        new = reversed_execution_stack[_start:_end][::-1][:-1]
                        _found = False
                        for _id, _label in enumerate(
                            list(
                                reversed(
                                    self._verify_chain[last_writer_func][
                                        str(int(last_writer_id))
                                    ]["nodes"][: int(last)]
                                )
                            )
                        ):
                            if not _label.startswith("write"):
                                last = last - 1 - _id
                                _found = True
                                break
                        if not _found:
                            return False
                        _split = new.split(":")
                        if self._verify_chain[last_writer_func][
                            str(int(last_writer_id))
                        ]["nodes"][last] != "{}:{}".format(
                            _split[0], _split[2]
                        ):
                            return False
                        _split = new.split(":")
                        new = "<{}>".format(new)
                        if not self._is_valid_execution(
                            new, _split[0], _split[2]
                        ):
                            return False
                        internal = True
                    elif char == ",":
                        cur += 1
                    else:
                        tmp = cur
                        tmp_internal = False
                        for _index, _char in enumerate(
                            reversed_execution_stack[cur:]
                        ):
                            if _char == "<":
                                cur += _index
                                break
                            if _char == ",":
                                tmp_internal = True
                                cur += _index
                                break
                        new = reversed_execution_stack[tmp - 1 : cur][::-1][
                            :-1
                        ]
                        if internal:
                            _found = False
                            for _id, a in enumerate(
                                list(
                                    reversed(
                                        self._verify_chain[last_writer_func][
                                            str(int(last_writer_id))
                                        ]["nodes"][: int(last)]
                                    )
                                )
                            ):
                                if not a.startswith("write"):
                                    last = last - 1 - _id
                                    _found = True
                                    break
                            if not _found:
                                return False
                            _split = new.split(":")
                            if tmp_internal:
                                if self._verify_chain[last_writer_func][
                                    str(int(last_writer_id))
                                ]["nodes"][last] != "{}:{}".format(
                                    _split[0], _split[2]
                                ):
                                    return False
                            else:
                                if self._verify_chain[last_writer_func][
                                    str(int(last_writer_id))
                                ]["nodes"][last] != "start: {}:{}".format(
                                    _split[0], _split[2]
                                ):
                                    return False
                        else:
                            _split = new.split(":")
                            _found = False
                            for _id, _label in enumerate(
                                list(
                                    reversed(
                                        self._verify_chain[_split[0]][
                                            str(int(_split[2]))
                                        ]["nodes"]
                                    )
                                )
                            ):
                                if not _label.startswith("write"):
                                    if _label == "{}:{}".format(
                                        last_writer_func, last_writer_id
                                    ):
                                        last_writer_func = _split[0]
                                        last_writer_id = _split[2]
                                        last = (
                                            len(
                                                self._verify_chain[
                                                    last_writer_func
                                                ][str(int(last_writer_id))][
                                                    "nodes"
                                                ]
                                            )
                                            - 1
                                            - _id
                                        )
                                        _found = True
                                        break
                            if not _found:
                                return False
                        internal = tmp_internal
                        cur += 1
                tmp_id = 0
                for _id, _label in enumerate(
                    list(
                        reversed(
                            self._verify_chain[last_writer_func][
                                str(int(last_writer_id))
                            ]["nodes"][: int(last)]
                        )
                    )
                ):
                    if not _label.startswith("write"):
                        tmp_id = last - 1 - _id
                        break
                if tmp_id != 0:
                    return False
            else:  # never happens
                return False
        return True
