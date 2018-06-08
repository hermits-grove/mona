pub fn boxed(strs: &Vec<String>, pad: usize) -> Vec<String> {
    let longest_line = strs.iter()
        .map(|s| s.chars().count())
        .max()
        .unwrap_or(0);

    let mut boxed = Vec::new();
    boxed.push(format!("╭{}╮", "─".repeat(longest_line + 2 * pad)));
    for s in strs {
        let chars = s.chars().count();
        let suffix = " ".repeat(longest_line - chars);
        let space = " ".repeat(pad);
        boxed.push(format!("│{}{}{}{}│", space, s, suffix, space))
    }
    boxed.push(format!("╰{}╯", "─".repeat(longest_line + 2 * pad)));
    boxed
}
