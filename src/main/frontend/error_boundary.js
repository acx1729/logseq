import React from "react";

/**
 * Catches render errors below it. `fallback` is an element or a function of
 * {error, resetError}; `onError` receives the error and React's info.
 */
export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    if (typeof this.props.onError === "function") {
      this.props.onError(error, info);
    }
  }

  render() {
    if (this.state.error) {
      const { fallback } = this.props;
      if (typeof fallback === "function") {
        return fallback({ error: this.state.error, resetError: () => this.setState({ error: null }) });
      }
      return fallback === undefined ? null : fallback;
    }
    return this.props.children;
  }
}
