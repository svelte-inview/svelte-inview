declare namespace svelte.JSX {
  export interface HTMLProps<T> {
    // If you want to use inviewchange
    oninviewchange?: (someArg: number) => string;
  }
}
