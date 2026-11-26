//! Bounded, preallocated DSP graph foundation.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NodeId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NodeConfig {
    PassThrough,
    Gain { linear_gain: f32 },
    PeakMeter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DspError {
    EmptyGraph,
    AllocationFailed,
    InvalidNodeId,
    SelfConnection,
    MultipleInputs,
    MultipleRoots,
    CycleDetected,
    MissingOutput,
    InvalidFrameCapacity,
    InvalidFrameCount,
    InputLengthMismatch,
    InvalidGain,
    NonFiniteInput,
    NonFiniteOutput,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BlockMetrics {
    pub peak: f32,
    pub rms: f32,
}

pub struct DspGraphBuilder {
    nodes: Vec<NodeConfig>,
    edges: Vec<(NodeId, NodeId)>,
    output: Option<NodeId>,
}

impl DspGraphBuilder {
    pub fn new() -> Self {
        Self { nodes: Vec::new(), edges: Vec::new(), output: None }
    }

    pub fn add_node(&mut self, config: NodeConfig) -> Result<NodeId, DspError> {
        if let NodeConfig::Gain { linear_gain } = config
            && (!linear_gain.is_finite() || !(0.0..=16.0).contains(&linear_gain))
        {
            return Err(DspError::InvalidGain);
        }
        if self.nodes.len() >= u32::MAX as usize {
            return Err(DspError::InvalidNodeId);
        }
        self.nodes.try_reserve(1).map_err(|_| DspError::AllocationFailed)?;
        let id = NodeId(self.nodes.len() as u32);
        self.nodes.push(config);
        Ok(id)
    }

    pub fn connect(&mut self, source: NodeId, destination: NodeId) -> Result<(), DspError> {
        if !self.contains(source) || !self.contains(destination) {
            return Err(DspError::InvalidNodeId);
        }
        if source == destination {
            return Err(DspError::SelfConnection);
        }
        if self.edges.iter().any(|(_, target)| *target == destination) {
            return Err(DspError::MultipleInputs);
        }
        self.edges.try_reserve(1).map_err(|_| DspError::AllocationFailed)?;
        self.edges.push((source, destination));
        Ok(())
    }

    pub fn set_output(&mut self, output: NodeId) -> Result<(), DspError> {
        if !self.contains(output) {
            return Err(DspError::InvalidNodeId);
        }
        self.output = Some(output);
        Ok(())
    }

    pub fn prepare(self, max_frames: usize) -> Result<DspGraph, DspError> {
        let count = self.nodes.len();
        if count == 0 {
            return Err(DspError::EmptyGraph);
        }
        if max_frames == 0 {
            return Err(DspError::InvalidFrameCapacity);
        }
        let output = self.output.ok_or(DspError::MissingOutput)?;
        let edge_count = self.edges.len();
        let mut incoming = Vec::<Option<NodeId>>::new();
        incoming.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        incoming.resize(count, None);

        let mut indegree = Vec::<usize>::new();
        indegree.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        indegree.resize(count, 0);

        let mut outdegree = Vec::<usize>::new();
        outdegree.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        outdegree.resize(count, 0);

        for (source, destination) in &self.edges {
            let from = source.0 as usize;
            let to = destination.0 as usize;
            if incoming[to].is_some() {
                return Err(DspError::MultipleInputs);
            }
            incoming[to] = Some(*source);
            indegree[to] += 1;
            outdegree[from] += 1;
        }

        let mut outgoing = Vec::<Vec<usize>>::new();
        outgoing.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        for degree in outdegree {
            let mut destinations = Vec::<usize>::new();
            destinations.try_reserve_exact(degree).map_err(|_| DspError::AllocationFailed)?;
            outgoing.push(destinations);
        }
        for (source, destination) in &self.edges {
            outgoing[source.0 as usize].push(destination.0 as usize);
        }
        debug_assert_eq!(self.edges.len(), edge_count);

        let roots = indegree.iter().filter(|degree| **degree == 0).count();
        if roots != 1 {
            return Err(DspError::MultipleRoots);
        }

        // Kahn topological sort; all allocations happen in prepare, never process.
        let mut ready = Vec::<usize>::new();
        ready.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        for (index, degree) in indegree.iter().enumerate() {
            if *degree == 0 {
                ready.push(index);
            }
        }
        let mut order = Vec::<NodeId>::new();
        order.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        let mut cursor = 0usize;
        while cursor < ready.len() {
            let node = ready[cursor];
            cursor += 1;
            order.push(NodeId(node as u32));
            for &next in &outgoing[node] {
                indegree[next] -= 1;
                if indegree[next] == 0 {
                    ready.push(next);
                }
            }
        }
        if order.len() != count {
            return Err(DspError::CycleDetected);
        }

        let mut buffers = Vec::<Vec<f32>>::new();
        buffers.try_reserve_exact(count).map_err(|_| DspError::AllocationFailed)?;
        for _ in 0..count {
            let mut buffer = Vec::<f32>::new();
            buffer.try_reserve_exact(max_frames).map_err(|_| DspError::AllocationFailed)?;
            buffer.resize(max_frames, 0.0f32);
            buffers.push(buffer);
        }
        Ok(DspGraph {
            nodes: self.nodes,
            order,
            input_from: incoming,
            buffers,
            output,
            max_frames,
            last_metrics: BlockMetrics::default(),
        })
    }

    fn contains(&self, id: NodeId) -> bool {
        (id.0 as usize) < self.nodes.len()
    }
}

impl Default for DspGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DspGraph {
    nodes: Vec<NodeConfig>,
    order: Vec<NodeId>,
    input_from: Vec<Option<NodeId>>,
    buffers: Vec<Vec<f32>>,
    output: NodeId,
    max_frames: usize,
    last_metrics: BlockMetrics,
}

impl DspGraph {
    /// Processes into graph-owned buffers. No per-block heap allocation occurs.
    /// Input must be finite and exactly frame_count samples (mono).
    pub fn process(&mut self, input: &[f32], frame_count: usize) -> Result<&[f32], DspError> {
        if frame_count == 0 || frame_count > self.max_frames {
            return Err(DspError::InvalidFrameCount);
        }
        if input.len() != frame_count {
            return Err(DspError::InputLengthMismatch);
        }
        if input.iter().any(|sample| !sample.is_finite()) {
            return Err(DspError::NonFiniteInput);
        }

        let nodes = &self.nodes;
        let order = &self.order;
        let input_from = &self.input_from;
        let buffers = &mut self.buffers;

        for ordered_node in order.iter() {
            let node_id = ordered_node.0 as usize;
            match input_from[node_id] {
                None => {
                    process_node(nodes[node_id], &input[..frame_count], &mut buffers[node_id][..frame_count])?;
                }
                Some(source_id) => {
                    let source = source_id.0 as usize;
                    if source < node_id {
                        let (left, right) = buffers.split_at_mut(node_id);
                        process_node(
                            nodes[node_id],
                            &left[source][..frame_count],
                            &mut right[0][..frame_count],
                        )?;
                    } else {
                        let (left, right) = buffers.split_at_mut(source);
                        process_node(
                            nodes[node_id],
                            &right[0][..frame_count],
                            &mut left[node_id][..frame_count],
                        )?;
                    }
                }
            }
        }

        let output_index = self.output.0 as usize;
        let output = &buffers[output_index][..frame_count];
        if output.iter().any(|sample| !sample.is_finite()) {
            return Err(DspError::NonFiniteOutput);
        }
        let mut peak = 0.0f32;
        let mut sum_squares = 0.0f64;
        for &sample in output {
            peak = peak.max(sample.abs());
            sum_squares += (sample as f64) * (sample as f64);
        }
        self.last_metrics = BlockMetrics {
            peak,
            rms: (sum_squares / frame_count as f64).sqrt() as f32,
        };
        Ok(&self.buffers[output_index][..frame_count])
    }

    pub fn last_metrics(&self) -> BlockMetrics {
        self.last_metrics
    }
}

fn process_node(config: NodeConfig, input: &[f32], output: &mut [f32]) -> Result<(), DspError> {
    if input.len() != output.len() {
        return Err(DspError::InputLengthMismatch);
    }
    match config {
        NodeConfig::Gain { linear_gain } => {
            for (out, sample) in output.iter_mut().zip(input.iter().copied()) {
                *out = sample * linear_gain;
            }
        }
        NodeConfig::PassThrough | NodeConfig::PeakMeter => output.copy_from_slice(input),
    }
    if output.iter().any(|sample| !sample.is_finite()) {
        return Err(DspError::NonFiniteOutput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_graph_applies_gain_and_reports_metrics() {
        let mut builder = DspGraphBuilder::new();
        let gain = builder.add_node(NodeConfig::Gain { linear_gain: 2.0 }).unwrap();
        let meter = builder.add_node(NodeConfig::PeakMeter).unwrap();
        builder.connect(gain, meter).unwrap();
        builder.set_output(meter).unwrap();
        let mut graph = builder.prepare(4).unwrap();

        let output = graph.process(&[0.1, -0.2, 0.3, -0.4], 4).unwrap();
        assert_eq!(output, &[0.2, -0.4, 0.6, -0.8]);
        assert!((graph.last_metrics().peak - 0.8).abs() < 0.0001);
        assert!((graph.last_metrics().rms - 0.5477226).abs() < 0.0001);
    }

    #[test]
    fn graph_rejects_cycle_and_multiple_incoming_edges() {
        let mut cyclic = DspGraphBuilder::new();
        let root = cyclic.add_node(NodeConfig::PassThrough).unwrap();
        let a = cyclic.add_node(NodeConfig::PassThrough).unwrap();
        let b = cyclic.add_node(NodeConfig::PassThrough).unwrap();
        cyclic.connect(a, b).unwrap();
        cyclic.connect(b, a).unwrap();
        cyclic.set_output(a).unwrap();
        assert_eq!(cyclic.prepare(8).err(), Some(DspError::CycleDetected));
        assert_eq!(root, NodeId(0));

        let mut multi = DspGraphBuilder::new();
        let x = multi.add_node(NodeConfig::PassThrough).unwrap();
        let y = multi.add_node(NodeConfig::PassThrough).unwrap();
        let z = multi.add_node(NodeConfig::PassThrough).unwrap();
        multi.connect(x, z).unwrap();
        assert_eq!(multi.connect(y, z), Err(DspError::MultipleInputs));
    }

    #[test]
    fn process_rejects_nan_before_mutating_graph_buffers() {
        let mut builder = DspGraphBuilder::new();
        let node = builder.add_node(NodeConfig::PassThrough).unwrap();
        builder.set_output(node).unwrap();
        let mut graph = builder.prepare(2).unwrap();
        assert_eq!(graph.process(&[f32::NAN], 1).err(), Some(DspError::NonFiniteInput));
        assert_eq!(graph.process(&[0.25], 1).unwrap(), &[0.25]);
    }

    #[test]
    fn invalid_gain_is_rejected_during_build() {
        let mut builder = DspGraphBuilder::new();
        assert_eq!(
            builder.add_node(NodeConfig::Gain { linear_gain: f32::INFINITY }),
            Err(DspError::InvalidGain),
        );
    }
}
