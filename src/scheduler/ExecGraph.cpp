#include "ExecGraph.h"

#include <sstream>
#include <util/json.h>

namespace scheduler {

    int countExecGraphNode(const ExecGraphNode &node) {
        int count = 1;

        if(!node.children.empty()) {
            for(auto c : node.children) {
                count += countExecGraphNode(c);
            }
        }

        return count;
    }

    int countExecGraphNodes(const ExecGraph &graph) {
        ExecGraphNode rootNode = graph.rootNode;
        int count = countExecGraphNode(rootNode);
        return count;
    }

    // ----------------------------------------
    // TODO - do this with RapidJson and not sstream
    // ----------------------------------------

    std::string execNodeToJson(const ExecGraphNode &node) {
        std::stringstream res;

        // Add the message
        res << "{ " << std::endl << "\"msg\": " << util::messageToJson(node.msg);

        // Add the children
        if (!node.children.empty()) {
            res << ", \"chained\": {" << std::endl;

            for (int i = 0; i < node.children.size(); i++) {
                res << execNodeToJson(node);

                if (i < node.children.size() - 1) {
                    res << ", " << std::endl;
                }
            }

            res << "}";
        }

        res << "}";

        return res.str();
    }

    std::string execGraphToJson(const ExecGraph &graph) {
        std::stringstream res;

        res << "{ " << std::endl << "\"root\": " << execNodeToJson(graph.rootNode) << std::endl << " }";

        return res.str();
    }
}

