import { reactive, createElement, createComponent } from "@vue/composition-api";
import { CreateElement } from "vue";
export function createPresenter<
  TProps extends Record<string, any>,
  TChildEvents extends object = Record<string, any>,
  TChildProps extends object = Record<string, any>,
  TTeg extends Parameters<CreateElement>[0] = Parameters<CreateElement>[0],
  TProps2 = TTeg extends { props: infer TRealProps }
    ? TRealProps extends Record<any, any>
      ? TRealProps
      : {}
    : {},
  T extends {
    [P in keyof TChildEvents]?: TChildEvents[P];
  } &
    { [P in keyof TChildProps]?: TChildProps[P] } = {
    [P in keyof TChildEvents]?: TChildEvents[P];
  } &
    { [P in keyof TChildProps]?: TChildProps[P] }
>(
  tag: TTeg,
  props: Record<keyof TProps, any>,
  additionalData: (props: TProps & TProps2) => T
) {
  return createComponent<Record<any, any>, any>({
    props: hasProps(tag) ? { ...tag.props, ...props } : props,
    setup(props) {
      const data1 = additionalData(props) || {};
      const presenter = Object.entries(data1).reduce(
        (acc, [f, v]) => {
          if (typeof v === "function") {
            acc.methods.push([f, v]);
          } else {
            const d = Object.getOwnPropertyDescriptor(data1, f);
            if (d) {
              Object.defineProperty(acc.props, f, d);
            }
          }
          return acc;
        },
        { methods: [], props: {} } as any
      );
      presenter.props = reactive(presenter.props);
      presenter.methods = presenter.methods.reduce((acc: any, [f, v]: any) => {
        acc[f] = v.bind(presenter.props);
        return acc;
      }, {});

      return {
        propsProxy: presenter.props,
        listenersProxy: presenter.methods
      };
    },
    render() {
      return createElement(tag, {
        attrs: this.$attrs,
        props: this.propsProxy,
        on: { ...(this.$listeners || {}), ...this.listenersProxy },
        scopedSlots: this.$scopedSlots
      });
    }
  });
}
function hasProps<TTeg>(tag: TTeg): tag is TTeg & { props: object } {
  return (
    typeof tag === "object" &&
    "props" in tag &&
    typeof (tag as any).props === "object"
  );
}
