import * as React from "react";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { cn } from "@/lib/utils";

export const Checkbox = React.forwardRef<
  React.ComponentRef<typeof CheckboxPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>
>(({ className, ...props }, ref) => (
  <CheckboxPrimitive.Root
    ref={ref}
    className={cn(
      "peer h-[17px] w-[17px] shrink-0 rounded-[3px] border-2 border-[#f6c33b] bg-[#f6c33b]/15 text-[#f6c33b] flex items-center justify-center cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-[#f6c33b]/25",
      className
    )}
    {...props}
  >
    <CheckboxPrimitive.Indicator className="flex items-center justify-center text-current">
      <span className="material-symbols-outlined !text-[14px]">check</span>
    </CheckboxPrimitive.Indicator>
  </CheckboxPrimitive.Root>
));
Checkbox.displayName = "Checkbox";
