import { Component, type ReactNode } from "react";

// ErrorBoundary keeps a render error in one page from blanking the whole
// SPA: it shows the message and a retry that re-mounts the subtree.
interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFrom(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flash err" style={{ margin: 16 }}>
          <strong>Something went wrong rendering this page.</strong>
          <div className="hash" style={{ marginTop: 6 }}>
            {this.state.error.message}
          </div>
          <button
            style={{ marginTop: 8 }}
            onClick={() => this.setState({ error: null })}
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}