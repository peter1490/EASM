import { HTMLAttributes, forwardRef } from "react";

type TableProps = HTMLAttributes<HTMLTableElement>;

const Table = forwardRef<HTMLTableElement, TableProps>(({ className = "", children, ...props }, ref) => {
  return (
    <div className="w-full overflow-auto rounded-lg border border-border">
      <table ref={ref} className={`w-full text-sm ${className}`} {...props}>
        {children}
      </table>
    </div>
  );
});

Table.displayName = "Table";

type TableHeaderProps = HTMLAttributes<HTMLTableSectionElement>;

const TableHeader = forwardRef<HTMLTableSectionElement, TableHeaderProps>(({ className = "", children, ...props }, ref) => {
  return (
    <thead ref={ref} className={`bg-muted ${className}`} {...props}>
      {children}
    </thead>
  );
});

TableHeader.displayName = "TableHeader";

type TableBodyProps = HTMLAttributes<HTMLTableSectionElement>;

const TableBody = forwardRef<HTMLTableSectionElement, TableBodyProps>(({ className = "", children, ...props }, ref) => {
  return (
    <tbody ref={ref} className={`[&_tr:last-child]:border-0 ${className}`} {...props}>
      {children}
    </tbody>
  );
});

TableBody.displayName = "TableBody";

type TableRowProps = HTMLAttributes<HTMLTableRowElement>;

const TableRow = forwardRef<HTMLTableRowElement, TableRowProps>(({ className = "", children, ...props }, ref) => {
  return (
    <tr
      ref={ref}
      className={`border-b border-border transition-colors hover:bg-muted/50 ${className}`}
      {...props}
    >
      {children}
    </tr>
  );
});

TableRow.displayName = "TableRow";

type TableHeadProps = HTMLAttributes<HTMLTableCellElement>;

const TableHead = forwardRef<HTMLTableCellElement, TableHeadProps>(({ className = "", children, ...props }, ref) => {
  return (
    <th
      ref={ref}
      className={`h-12 px-4 text-left align-middle font-semibold text-foreground [&:has([role=checkbox])]:pr-0 ${className}`}
      {...props}
    >
      {children}
    </th>
  );
});

TableHead.displayName = "TableHead";

type TableCellProps = HTMLAttributes<HTMLTableCellElement>;

const TableCell = forwardRef<HTMLTableCellElement, TableCellProps>(({ className = "", children, ...props }, ref) => {
  return (
    <td
      ref={ref}
      className={`p-4 align-middle [&:has([role=checkbox])]:pr-0 ${className}`}
      {...props}
    >
      {children}
    </td>
  );
});

TableCell.displayName = "TableCell";

export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell };

