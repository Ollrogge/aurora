use serde::{Deserialize, Serialize};
use std::collections::hash_map::Keys;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct BasicBlock {
    pub body: Vec<usize>,
    successors: HashSet<usize>,
    predecessors: HashSet<usize>,
}

impl BasicBlock {
    pub fn new() -> BasicBlock {
        let body = vec![];
        let successors = HashSet::new();
        let predecessors = HashSet::new();

        BasicBlock {
            body,
            successors,
            predecessors,
        }
    }
    pub fn start(&self) -> usize {
        *self.body.first().unwrap()
    }

    pub fn exit(&self) -> usize {
        *self.body.last().unwrap()
    }

    // basic blocks should not overlap so first address in block can be
    // seen as a kind of id ?
    pub fn id(&self) -> usize {
        self.body[0]
    }

    pub fn iter_addresses(&self) -> impl Iterator<Item = &usize> {
        self.body.iter()
    }
}

// bb = basic block
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    addr_to_bb_exit: HashMap<usize, usize>,
    exit_addr_to_bb: HashMap<usize, BasicBlock>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        // new bb
        let addr_to_bb_exit = HashMap::new();
        // last address before entering new bb
        let exit_addr_to_bb = HashMap::new();
        ControlFlowGraph {
            addr_to_bb_exit,
            exit_addr_to_bb,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.exit_addr_to_bb.is_empty()
    }

    pub fn keys(&self) -> Keys<usize, usize> {
        self.addr_to_bb_exit.keys()
    }

    pub fn get_instruction_successors(&self, address: usize) -> Vec<usize> {
        match self.exit_addr_to_bb.get(&address) {
            Some(bb) => bb.successors.iter().cloned().collect(),
            None => vec![],
        }
    }

    pub fn is_bb_end(&self, address: usize) -> bool {
        self.exit_addr_to_bb.contains_key(&address)
    }

    pub fn add_bb(&mut self, bb: BasicBlock) {
        for addr in bb.body.iter() {
            self.addr_to_bb_exit.insert(*addr, bb.exit());
        }
        self.exit_addr_to_bb.insert(bb.exit(), bb);
    }

    pub fn bbs(&self) -> impl Iterator<Item = &BasicBlock> {
        self.exit_addr_to_bb.values()
    }

    pub fn get_bb(&self, addr: usize) -> &BasicBlock {
        let exit_addr = self
            .addr_to_bb_exit
            .get(&addr)
            .expect(&format!("no exit address for {:x}", addr));
        let bb = self
            .exit_addr_to_bb
            .get(exit_addr)
            .expect(&format!("BB not found for exit address {:x}", exit_addr));

        bb
    }

    pub fn exists_path(&self, src: usize, dst: usize) -> bool {
        let mut work = Vec::new();
        work.push(src);

        while let Some(addr) = work.pop() {
            if addr == dst {
                return true;
            }
            let b = self.get_bb(addr);
            for successor in b.successors.iter() {
                work.push(successor.clone())
            }
        }

        false
    }

    pub fn in_same_bb(&self, addr1: usize, addr2: usize) -> bool {
        self.get_bb(addr1) == self.get_bb(addr2)
    }

    pub fn to_dot(&self) -> String {
        let mut ret = String::from_str("digraph {\n").unwrap();

        for bb in self.bbs() {
            for succ in bb.successors.iter() {
                ret.push_str(&format!("{} -> {}\n", bb.exit(), self.get_bb(*succ).exit()));
            }
        }
        ret.push_str("}\n");
        ret
    }

    pub fn heads(&self) -> Vec<usize> {
        self.bbs()
            .filter(|bb| bb.predecessors.is_empty())
            .map(|bb| bb.start())
            .collect()
    }

    pub fn leaves(&self) -> Vec<usize> {
        self.bbs()
            .filter(|bb| bb.successors.is_empty())
            .map(|bb| bb.start())
            .collect()
    }

    pub fn save(&self, output_dir: &String) {
        let file_path = format!("{}/cfg.json", output_dir);
        let serialized_string = serde_json::to_string(&self).unwrap();

        fs::write(&file_path, serialized_string)
            .expect(&format!("Could not write file {}", file_path));
    }

    pub fn load(input_dir: &String) -> Self {
        let file_path = format!("{}/cfg.json", input_dir);

        let content =
            fs::read_to_string(&file_path).expect(&format!("Could not read file {}", file_path));

        serde_json::from_str(&content).expect("Unable to deserialize cfg")
    }
}

pub struct CFGCollector {
    successors: HashMap<usize, HashSet<usize>>,
    predecessors: HashMap<usize, HashSet<usize>>,
}

impl CFGCollector {
    pub fn new() -> CFGCollector {
        CFGCollector {
            successors: HashMap::new(),
            predecessors: HashMap::new(),
        }
    }

    // also considers normal edges
    pub fn add_edge(&mut self, src: usize, dst: usize) {
        self.predecessors.entry(src).or_insert_with(HashSet::new);
        self.predecessors.entry(dst).or_insert_with(HashSet::new);

        self.successors.entry(src).or_insert_with(HashSet::new);
        self.successors.entry(dst).or_insert_with(HashSet::new);

        self.predecessors.get_mut(&dst).unwrap().insert(src);
        self.successors.get_mut(&src).unwrap().insert(dst);
    }

    pub fn heads(&self) -> Vec<usize> {
        let set: HashSet<_> = self.successors.keys().cloned().collect();
        set.into_iter()
            .filter(|k| !self.predecessors.contains_key(k) || self.predecessors[k].is_empty())
            .collect()
    }

    pub fn dfs(&self, start: usize) -> Vec<usize> {
        let mut ret = vec![];
        let mut todo = vec![start];
        let mut done = HashSet::new();

        while !todo.is_empty() {
            let node = todo.pop().unwrap();

            if done.contains(&node) {
                continue;
            }

            done.insert(node);
            ret.push(node);

            if let Some(successors) = self.successors.get(&node) {
                for successor in successors {
                    todo.push(*successor);
                }
            }
        }
        ret
    }

    pub fn construct_graph(&self) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new();
        let mut bb = BasicBlock::new();
        let mut finished = false;

        // find root edge ?
        let mut heads = self.heads();
        assert_eq!(heads.len(), 1);

        for node in self.dfs(heads.pop().unwrap()) {
            // current instruction is leading instruction
            if bb.body.is_empty() {
                for pred in self.predecessors[&node].iter() {
                    bb.predecessors.insert(*pred);
                }
            }

            // next instruction is leader
            if self.successors[&node].len() == 1
                && self.predecessors[&self.successors[&node].iter().last().unwrap()].len() != 1
            {
                for succ in self.successors[&node].iter() {
                    bb.successors.insert(*succ);
                }
                finished = true;
            }

            // more than one outgoing edges -> end of basic block
            if self.successors[&node].len() != 1 {
                for succ in self.successors[&node].iter() {
                    bb.successors.insert(*succ);
                }
                finished = true;
            }

            bb.body.push(node);

            if finished {
                cfg.add_bb(bb);
                bb = BasicBlock::new();
                finished = false;
            }
        }

        cfg
    }
}
