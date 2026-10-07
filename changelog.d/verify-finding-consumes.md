### Fixed: a finding check may consume the assets findings are on

- A tool implementing `verify.finding@1` (input: a finding) runs on the asset the finding is on, so its `consumes` may list any asset type. Before, the descriptor check refused every asset type, because the capability has no asset input port. Other capabilities still constrain `consumes` to their inputs.
