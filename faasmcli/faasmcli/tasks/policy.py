from invoke import task
import json
from os.path import join
from faasmcli.util.env import WASM_DIR
from faasmcli.util.crypto import encrypt_file, get_file_hash_digest
from faasmcli.util.wasm import parse_module
from graphviz import Digraph

FAASM_MAIN_FUNCTION_NAME = "_start"  # main function name of a faasm module


def _parse_cfg_to_dot(tree) -> Digraph:  # converts dot from cfg-tree
    """
    @param tree cfg tree
    """
    dot = Digraph(name="cfg")
    stack = list(reversed(tree.next))
    while len(stack) != 0:  # walk trough tree
        node = stack.pop()
        next_nodes = node.next
        outry_nodes = node.outry
        block = node.block
        dot.node(block.label, str(block))
        for next_node in next_nodes:
            next_block = next_node.block
            dot.node(next_block.label, str(next_block))
            dot.edge(block.label, next_block.label)
        for outry_node in outry_nodes:
            dot.edge(block.label, outry_node.block.label)
        stack += next_nodes
    return dot


@task(default=True, name="policy")
def policy(ctx, user, func, clean=False, debug=False):
    """
    Create policy file for function
    """
    user_path = join(WASM_DIR, user)
    function_path = join(user_path, func)
    entry_module_path = join(function_path, "function.wasm")
    encrypted_module_path = entry_module_path + ".enc"
    ccp_path = join(function_path, "policy.json")
    data = {}
    data["function"] = func
    key = encrypt_file(entry_module_path, encrypted_module_path)
    data["key"] = key
    data["hash_"] = get_file_hash_digest(entry_module_path, 0)
    data["hash"] = get_file_hash_digest(encrypted_module_path)
    module = parse_module(entry_module_path)
    possible_functions = module.get_chained_functions()
    chain_policy = ""
    allowed_functions = {}
    for tmp_func in possible_functions:
        tmp_func_path = join(user_path, tmp_func)
        tmp_func_path = join(tmp_func_path, "function.wasm")
        hash = get_file_hash_digest(tmp_func_path, 0)
        chain_policy += "<{},{}>,".format(tmp_func, hash)
        allowed_functions[tmp_func] = hash
    print(
        "{} allowed functions found for function '{}': {}".format(
            len(allowed_functions), func, allowed_functions
        )
    )
    data["ccp"] = chain_policy
    data["allowed-functions"] = allowed_functions
    verifies = {}
    chain_verifies = {}
    exported_start_func = module.export.get(FAASM_MAIN_FUNCTION_NAME)
    function = module.function.get(exported_start_func)
    if function is None:
        print(
            "error : Faasm main function (%s) not found!"
            % FAASM_MAIN_FUNCTION_NAME
        )
        return
    ccp_tree = module.create_verify(function, 0)
    dot = _parse_cfg_to_dot(ccp_tree)
    print(dot)
    dot.format = "dot_json"
    verifies[0] = json.loads(dot.pipe().decode("utf-8"))
    ccp_tree = module.create_ccp(function, 0)
    dot = _parse_cfg_to_dot(ccp_tree)
    dot.format = "dot_json"
    chain_verifies[0] = json.loads(dot.pipe().decode("utf-8"))
    for func in module.function:
        if func.name.startswith("$func_") and func.name.endswith("\\28\\29"):
            function = module.function.get(func)
            id = int(func.name[6:-6])
            ccp_tree = module.create_verify(func, id)
            dot = _parse_cfg_to_dot(ccp_tree)
            dot.format = "dot_json"
            verifies[id] = json.loads(dot.pipe().decode("utf-8"))
            ccp_tree = module.create_ccp(func, id)
            dot = _parse_cfg_to_dot(ccp_tree)
            dot.format = "dot_json"
            chain_verifies[id] = json.loads(dot.pipe().decode("utf-8"))
    data["chain-verify"] = chain_verifies
    data["verify"] = verifies
    with open(ccp_path, "w", encoding="utf-8") as policy_file:
        json.dump(
            data, policy_file, ensure_ascii=False, indent=4
        )  # for beauty print
        print("policy file written to %s" % ccp_path)
